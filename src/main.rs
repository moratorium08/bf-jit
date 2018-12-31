#![feature(asm)]
use std::io::{self, Read};
use std::str::Chars;
use std::vec;

const MEMSIZE: usize = 300000;
const DEBUG: bool = false;

/* JITの構造 
* Machine Codeモードではcl = 1であることを仮定、現在のメモリ位置をrbxで取ることを仮定
* また、Machine Codeからもどるときはrbxの値が最終的に指しているメモリの位置とする
* またr10にbf_read_fun, r11にbf_write_funを代入しておく 
* 
* 以上より各bfの命令は基本的には、
* [next] inc rbx
* [prev] dec rbx
* [inc]  add [rbx], cl
* [dec]  sub [rbx], cl
* [out]  call r10
* [in]   call r11
* [sub]  mov rax, <addr>, call rax
* とでき、さらにSubの前後はprologueとepilogueがあり、
* prologue:
*   mov rax, [rbx]; test rax, rax; je <epilogue>
* body:
*   ...
*   mov rax, [rbx]; test rax, rax; jne <body>
* epilogue:
*   ret 
* と変換すれば良い。epilogueは、JITから戻る部分で、基本的にcallで読んでいくので、
* ただretすればいい
*/

#[link(name = "bf_lib")]
extern {
    static bf_read_fun: u64;
    static bf_write_fun: u64;
}


const inc_rdi: [u8; 3] = [0x48, 0xff, 0xc3];
const dec_rdi: [u8; 3] = [0x48, 0xff, 0xcb];
const add_mem: [u8; 2] = [0x00, 0x0b];
const sub_mem: [u8; 2] = [0x28, 0x0b];
const out_mem: [u8; 3] = [0x41, 0xff, 0xd2];
const in_mem:  [u8; 3] = [0x41, 0xff, 0xd3];
const je:      [u8; 1] = [0xe9]; 
const jne:     [u8; 2] = [0x0f, 0x85];
const ret:     [u8; 1] = [0xc3];

fn gen_je(addr: i32) -> [u8; 5] {
    let addr = (addr - 5) as u32;
    let b4 : u8 = ((addr >> 24) & 0xff) as u8;
    let b3 : u8 = ((addr >> 16) & 0xff) as u8;
    let b2 : u8 = ((addr >> 8) & 0xff) as u8;
    let b1 : u8 = (addr & 0xff) as u8;
    [je[0], b1, b2, b3, b4]
}
fn gen_jne(addr: i32) -> [u8; 6] {
    let addr = (addr - 6) as u32;
    let b4 : u8 = ((addr >> 24) & 0xff) as u8;
    let b3 : u8 = ((addr >> 16) & 0xff) as u8;
    let b2 : u8 = ((addr >> 8) & 0xff) as u8;
    let b1 : u8 = (addr & 0xff) as u8;
    [jne[0], jne[1], b1, b2, b3, b4]
}

fn gen_sub(addr: i64) -> [u8; 12] {
    let addr = addr as u64;
    let b8 : u8 = ((addr >> 56) & 0xff) as u8;
    let b7 : u8 = ((addr >> 48) & 0xff) as u8;
    let b6 : u8 = ((addr >> 40) & 0xff) as u8;
    let b5 : u8 = ((addr >> 32) & 0xff) as u8;
    let b4 : u8 = ((addr >> 24) & 0xff) as u8;
    let b3 : u8 = ((addr >> 16) & 0xff) as u8;
    let b2 : u8 = ((addr >> 8) & 0xff) as u8;
    let b1 : u8 = (addr & 0xff) as u8;
    [0x48, 0xb8, b1, b2, b3, b4, b5, b6, b7, b8, 0xff, 0xd0]
}

fn gen_prologue(body_size: usize) -> [u8; 11] {
    let b = gen_je(body_size as i32);
    // mov rax, [rbx] 48 8b 03
    // test rax, rax  48 85 c0
    // je epilogue
    [0x48, 0x8b, 0x3, 0x48, 0x85, 0xc0, b[0], b[1], b[2], b[3], b[4]]
}
fn gen_body_tail(body_size: usize) -> [u8; 12] {
    let body_size = body_size + 6;
    let b = gen_jne(-(body_size as i32));
    // mov rax, [rbx] 48 8b 03
    // test rax, rax  48 85 c0
    // jne 
    [0x48, 0x8b, 0x3, 0x48, 0x85, 0xc0, b[0], b[1], b[2], b[3], b[4], b[5]]
}

fn enter_jit(mem: &[u8; MEMSIZE], ptr: usize, jit: u64) -> usize {
    let result: usize;
    unsafe {
        let addr = mem as *const u8;
        let memaddr = addr as u64;
        let addr = memaddr + (ptr as u64);
        
        let result_addr: u64;
        asm!("mov $1, cl\n
              mov %1, %r10\n
              mov %2, %r11n
              mov %3, %rbx\n
              mov %4, %rax\n
              call %rax\n
              mov %rbx, %0" 
              : "=r"(result_addr)
              : "r" (bf_read_fun), 
                "r" (bf_write_fun),
                "r" (addr),
                "r" (jit)
              : "rcx");
        
        result = (result_addr - memaddr) as usize;
    }
    result
}

enum Op {
    Next,
    Prev,
    Inc,
    Dec,
    Out,
    In,
    Sub(Sub)
}

struct Sub {
    ops: vec::Vec<Op>,
    count: u32,
    is_global: bool
}

struct Asm {
    ops: vec::Vec<u8>
}

impl Asm {
    fn new(ops: vec::Vec<u8>) -> Asm {
        Asm{ops}
    }
    fn empty() -> Asm {
        Asm{ops: vec![]}
    }
    fn push(&mut self, asm: Asm) {
        for op in asm.ops {
            self.ops.push(op);
        }
    }
}

impl Sub {
    fn new(ops: vec::Vec<Op>, is_global: bool) -> Sub {
        Sub{ops: ops, count: 0, is_global}
    }

    // rdiに現在のテープの位置
    fn compile(&self, mut pos: u32) -> Asm {
        let mut asm = Asm::empty();
        for op in self.ops.iter() {
            //asm.push(op.compile(pos);)
        }
        asm
    }
}

impl Op {
    fn parse(iter: &mut Chars, is_global: bool) -> Result<Sub, String> {
        let mut v = vec::Vec::new();
        while let Some(c) = iter.next() {
            match c {
                '>' => v.push(Op::Next),
                '<' => v.push(Op::Prev),
                '+' => v.push(Op::Inc),
                '-' => v.push(Op::Dec),
                '.' => v.push(Op::Out),
                ',' => v.push(Op::In),
                '[' => {
                    let ops = Op::parse(iter, false)?;
                    v.push(Op::Sub(ops));
                },
                ']' => {
                    if is_global {
                        return Err(format!("mismatch ]"));
                    }
                    return Ok(Sub::new(v, is_global));
                },
                ' ' | '\n' | '\t' => (),
                x => {
                    return Err(format!("{} is invalid character", x));
                }
            }
        }
        Ok(Sub::new(v, is_global))
    }
    fn compile(&self, pos: u32) -> Asm {
        let v = 
        match self {
            Op::Next   => inc_rdi.to_vec(),
            Op::Prev   => inc_rdi.to_vec(),
            Op::Inc    => inc_rdi.to_vec(),
            Op::Dec    => inc_rdi.to_vec(),
            Op::Out    => inc_rdi.to_vec(),
            Op::In     => inc_rdi.to_vec(),
            Op::Sub(s) => inc_rdi.to_vec(),
        };
        Asm::new(v)
    }
}

struct Env {
    mem: [u8; MEMSIZE],
    addr: usize,
}

impl Env {
    fn new(mem_size: usize) -> Env {
        Env{mem: [0; MEMSIZE], addr: 0}
    }

    fn dump(&self) {
        println!("addr: {}", self.addr);
        println!();
    }

    fn run<'a>(&mut self, sub: &mut Sub, is_global: bool) -> Result<(), &str> {
        let mx = sub.ops.len();
        sub.count += 1;
        let mut pc = 0usize;
        loop {
            if pc >= mx {
                if !is_global && self.mem[self.addr] != 0 {
                    pc = 0;
                    continue;
                }
                break;
            }
            if DEBUG {
                self.dump();
            }
            let current_pc = pc;
            pc += 1;
            match sub.ops[current_pc] {
                Op::Next => self.addr += 1,
                Op::Prev => self.addr -= 1,
                Op::Inc => self.mem[self.addr] += 1,
                Op::Dec => self.mem[self.addr] -= 1,
                Op::Out => print!("{}", self.mem[self.addr] as char),
                Op::In => {
                    match io::stdin().lock().bytes().next() {
                        Some(c) => match c {
                            Ok(c) => self.mem[self.addr] = c,
                            Err(_) => return Err("error: stdin")
                        }
                        None => return Err("stdin closed")
                    }
                },
                Op::Sub(ref mut s) => {
                    s.count += 1;
                    if self.mem[self.addr] != 0 {
                        match self.run(s, false) {
                            Ok(()) => (),
                            Err(_) => return Err("error")
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    match Op::parse(&mut buffer.chars(), true) {
        Ok(mut ops) => {
            let mut env = Env::new(MEMSIZE);
            match env.run(&mut ops, true) {
                Ok(_) => (),
                Err(s) => println!("{}", s)
            }
        },
        Err(reason) => {
            println!("Failed to run: {}", reason);
        }
    }
    Ok(())
}
