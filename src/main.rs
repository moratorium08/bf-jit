use std::io::{self, Read};
use std::str::Chars;
use std::vec;

const MEMSIZE: usize = 300000;
const DEBUG: bool = false;

const inc_rdi: [u8; 3] = [0x48, 0xff, 0xc7];
const dec_rdi: [u8; 3] = [0x48, 0xff, 0xcf];
const add_mem: [u8; 2] = [0x00, 0x07];
const sub_mem: [u8; 2] = [0x28, 0x07];


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
* [sub]  j [addr]
* とでき、さらにSubの前後はprologueとepilogueがあり、
* prologue:
*   mov rax, [rbx]; test rax, rax; je [epilogue]
* body:
*   mov rax, [rbx]; test rax, rax; jne [body]
*   ...
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
        for op in self.ops {
            asm.push(op.compile(pos);)
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
        match self.op {
            Next => 
        }
    }
}

struct Env {
    mem: vec::Vec<u8>,
    addr: usize,
}

impl Env {
    fn new(mem_size: usize) -> Env {
        Env{mem: vec![0; mem_size], addr: 0}
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
