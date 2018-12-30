use std::io::{self, Read};
use std::str::Chars;
use std::vec;

const MEMSIZE: usize = 300000;
const DEBUG: bool = false;

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
}

impl Sub {
    fn new(ops: vec::Vec<Op>) -> Sub {
        Sub{ops: ops, count: 0}
    }
}

impl Op {
    fn parse(iter: &mut Chars, is_global: bool) -> Result<vec::Vec<Op>, String> {
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
                    v.push(Op::Sub(Sub::new(ops)));
                },
                ']' => {
                    if is_global {
                        return Err(format!("mismatch ]"));
                    }
                    return Ok(v);
                },
                ' ' | '\n' | '\t' => (),
                x => {
                    return Err(format!("{} is invalid character", x));
                }
            }
        }
        Ok(v)
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

    fn run<'a>(&mut self, ops: &mut vec::Vec<Op>, is_global: bool) -> Result<(), &str> {
        let mx = ops.len();
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
            match ops[current_pc] {
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
                        match self.run(&mut s.ops, false) {
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
