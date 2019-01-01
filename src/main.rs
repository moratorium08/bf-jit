#![feature(asm)]
#![feature(libc)]
extern crate libc;
use libc::c_void;
use std::io::{self, Read};
use std::mem;
use std::str::Chars;
use std::vec;

const MEMSIZE: usize = 300000;
const DEBUG: bool = true;
const THRESHOLD: u64 = 2;
const PAGESIZE: usize = 4096;

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
*   mov al, [rbx]; test al, al; je <epilogue>
* body:
*   ...
*   mov al, [rbx]; test al, al; jne <body>
* epilogue:
*   ret 
* と変換すれば良い。epilogueは、JITから戻る部分で、基本的にcallで読んでいくので、
* ただretすればいい
*/

#[link(name = "bf", kind="static")]
extern {
    fn bf_read_fun ();
    fn bf_write_fun ();
}


const INC_RDI: [u8; 3] = [0x48, 0xff, 0xc3];
const DEC_RDI: [u8; 3] = [0x48, 0xff, 0xcb];
const ADD_MEM: [u8; 2] = [0x00, 0x0b];
const SUB_MEM: [u8; 2] = [0x28, 0x0b];
const OUT_MEM: [u8; 3] = [0x41, 0xff, 0xd2];
const IN_MEM:  [u8; 3] = [0x41, 0xff, 0xd3];
const JE:      [u8; 2] = [0x0f, 0x84]; 
const JNE:     [u8; 2] = [0x0f, 0x85];
const RET:     [u8; 1] = [0xc3];

fn gen_je(addr: i32) -> [u8; 6] {
    let addr = (addr - 6) as u32;
    let b4 : u8 = ((addr >> 24) & 0xff) as u8;
    let b3 : u8 = ((addr >> 16) & 0xff) as u8;
    let b2 : u8 = ((addr >> 8) & 0xff) as u8;
    let b1 : u8 = (addr & 0xff) as u8;
    [JE[0], JE[1], b1, b2, b3, b4]
}
fn gen_jne(addr: i32) -> [u8; 6] {
    let addr = (addr - 6) as u32;
    let b4 : u8 = ((addr >> 24) & 0xff) as u8;
    let b3 : u8 = ((addr >> 16) & 0xff) as u8;
    let b2 : u8 = ((addr >> 8) & 0xff) as u8;
    let b1 : u8 = (addr & 0xff) as u8;
    [JNE[0], JNE[1], b1, b2, b3, b4]
}

fn gen_sub(addr: u64) -> [u8; 12] {
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

fn gen_prologue(body_size: usize) -> [u8; 10] {
    let b = gen_je((body_size + 4 + 2 /* hmmm bug.. please tell me why */) as i32);
    // mov al, [rbx] 8a 03
    // test al, al   84 c0
    // je epilogue
    [0x8a, 0x3, 0x84, 0xc0, b[0], b[1], b[2], b[3], b[4], b[5]]
}
fn gen_body_tail(body_size: usize) -> [u8; 10] {
    let body_size = body_size + 4;
    let b = gen_jne(-(body_size as i32));
    // mov al, [rbx] 8a 03
    // test al, al   84 c0
    // jne 
    [0x8a, 0x3, 0x84, 0xc0, b[0], b[1], b[2], b[3], b[4], b[5]]
}

fn enter_jit(mem: &[u8; MEMSIZE], ptr: usize, jit: u64) -> usize {
    if DEBUG {
        eprintln!("entering jit code...");
    }
    let result: usize;
    unsafe {
        let addr = mem as *const u8;
        let base_memaddr = addr as u64;
        let memaddr = base_memaddr + (ptr as u64);

        let addr = bf_read_fun as *const u8;
        let bf_read_fun_addr = addr as u64;

        let addr = bf_write_fun as *const u8;
        let bf_write_fun_addr = addr as u64;
        
        let result_addr: u64;
        asm!("mov cl, 1
              mov r10, $1
              mov r11, $2
              mov rbx, $3
              mov rax, $4
              call rax
              mov $0, rbx" 
              : "=&r"(result_addr)
              : "r" (bf_read_fun_addr), 
                "r" (bf_write_fun_addr),
                "r" (memaddr),
                "r" (jit)
              : "rcx", "rbx", "rax", "r10", "r11"
              : "intel");
        
        result = (result_addr - base_memaddr) as usize;
    }
    result
}
fn mmap(asm: Asm) -> u64 {
    unsafe {
        let program: *mut u8;
        let page: *mut c_void = libc::mmap(
            ::std::ptr::null_mut(),
            Env::page_size(asm.size()),
            libc::PROT_EXEC | libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            0,
            0);
        program = mem::transmute(page);
        program.copy_from_nonoverlapping(asm.ops.as_ptr(), asm.size());
        let ptr: u64 = mem::transmute(page);
        ptr
    }
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
    count: u64,
    is_global: bool,
    machine_code: Option<u64>
}

struct Asm {
    pub ops: vec::Vec<u8>
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
    fn size(&self) -> usize {
        self.ops.len()
    }
}

impl Sub {
    fn new(ops: vec::Vec<Op>, is_global: bool) -> Sub {
        Sub{ops: ops, count: 0, is_global, machine_code: None}
    }

    fn compile(&self) -> Asm {
        let mut body = Asm::empty();
        for op in self.ops.iter() {
            let asm = op.compile();
            body.push(asm);
        }
        if self.is_global {
            body.push(Asm::new(RET.to_vec()));
            body
        } else{
            // body tail
            body.push(Asm::new(gen_body_tail(body.size()).to_vec()));

            let mut sub = Asm::empty();
            sub.push(Asm::new(gen_prologue(body.size()).to_vec()));
            sub.push(body);
            sub.push(Asm::new(RET.to_vec()));
            sub 
        }
    }
    fn countup(&mut self) {
        self.count += 1;
        match self.machine_code {
            Some(_) => (),
            None => {
                if self.count > THRESHOLD {
                    let asm = self.compile();
                    let addr = mmap(asm);
                    self.machine_code = Some(addr);
                }
            }
        }
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
    fn compile(&self) -> Asm {
        let v = 
        match self {
            Op::Next   => INC_RDI.to_vec(),
            Op::Prev   => DEC_RDI.to_vec(),
            Op::Inc    => ADD_MEM.to_vec(),
            Op::Dec    => SUB_MEM.to_vec(),
            Op::Out    => OUT_MEM.to_vec(),
            Op::In     => IN_MEM.to_vec(),
            Op::Sub(s) => {
                match s.machine_code {
                    Some(addr) => gen_sub(addr).to_vec(),
                    None => {
                        let asm = s.compile();
                        asm.ops
                    }
                }
            },
        };
        Asm::new(v)
    }
}

struct Env {
    mem: [u8; MEMSIZE],
    addr: usize,
}

impl Env {
    fn new() -> Env {
        Env{mem: [0; MEMSIZE], addr: 0}
    }

    fn page_size(size: usize) -> usize {
        let x = size % PAGESIZE;
        if x == 0 {
            size
        } else {
            size + PAGESIZE - (size % PAGESIZE)
        }
    }

    fn run<'a>(&mut self, sub: &mut Sub, is_global: bool) -> Result<(), &str> {
        let mx = sub.ops.len();
        sub.countup();
        match sub.machine_code {
            Some(addr) => {
                self.addr = enter_jit(&self.mem, self.addr, addr);
                return Ok(());
            },
            None => ()
        }
        let mut pc = 0usize;
        loop {
            if pc >= mx {
                if !is_global && self.mem[self.addr] != 0 {
                    match self.run(sub, false) {
                        Ok(()) => (),
                        Err(_) => return Err("error")
                    }
                }
                break;
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
            let mut env = Env::new();
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
