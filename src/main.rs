#![feature(asm)]
#![feature(libc)]
#[macro_use]
extern crate clap;
extern crate libc;
#[macro_use]
extern crate lazy_static;
use libc::c_void;
use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::str::Chars;
use std::vec;

const MEMSIZE: usize = 600000;
const INITIAL_MEM_ADDR: usize = 300000;
const DEBUG: bool = false;
const USE_JIT: bool = true;
const THRESHOLD: u64 = 2;
const DEFAULT_FILENAME: &str = "a.bf";
const PAGESIZE: usize = 4096;

struct Param {
    pub debug: bool,
    pub use_jit: bool,
    pub threshold: u64,
    pub filename: String,
}

struct ParamBuilder {
    debug_tmp: bool,
    use_jit_tmp: bool,
    threshold_tmp: u64,
    filename_tmp: String
}

impl Param {
    fn new(builder: ParamBuilder) -> Param {
        Param{
            debug: builder.debug_tmp,
            use_jit: builder.use_jit_tmp,
            threshold: builder.threshold_tmp,
            filename: builder.filename_tmp,
        }
    }
}

impl ParamBuilder {
    fn new() -> ParamBuilder {
        ParamBuilder {
            debug_tmp: DEBUG, 
            use_jit_tmp: USE_JIT, 
            threshold_tmp: THRESHOLD,
            filename_tmp: String::from(DEFAULT_FILENAME)}
    }
    fn debug(self, debug_tmp: bool) -> ParamBuilder {
        ParamBuilder{debug_tmp, ..self}
    }
    fn use_jit(self, use_jit_tmp: bool) -> ParamBuilder {
        ParamBuilder{use_jit_tmp, ..self}
    }
    fn threshold(self, threshold_tmp: u64) -> ParamBuilder {
        ParamBuilder{threshold_tmp, ..self}
    }
    fn filename(self, filename_tmp: String) -> ParamBuilder {
        ParamBuilder{filename_tmp, ..self}
    }
    fn build(self) -> Param {
        Param::new(self)
    }
}

lazy_static! {
    static ref PARAM: Param =  {
        let argparse = clap::App::new("bf-jit")
                            .version("1.0")
                            .author("moratorium08")
                            .arg(clap::Arg::with_name("filename")
                                        .help("input file to run")
                                        .index(1)
                                        .required(true))
                            .arg(clap::Arg::with_name("debug")
                                        .help("debug mode")
                                        .long("debug")
                                        )
                            .arg(clap::Arg::with_name("no-jit")
                                        .help("jit mode")
                                        .long("no-jit")
                                        )
                            .arg(clap::Arg::with_name("threshold")
                                        .help("jit compile threshold")
                                        .long("threshold")
                                        .short("t")
                                        )
                            .get_matches();
        
        let filename = argparse.value_of("filename").unwrap_or(DEFAULT_FILENAME);
        let debug = argparse.is_present("debug");
        let jit_mode = !argparse.is_present("no-jit");
        let threshold = value_t!(argparse, "threshold", u64).unwrap_or(THRESHOLD);
        ParamBuilder::new()
            .debug(debug)
            .use_jit(jit_mode)
            .threshold(threshold)
            .filename(String::from(filename))
            .build()
    };
}

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
const IN_MEM:  [u8; 3] = [0x41, 0xff, 0xd2];
const OUT_MEM: [u8; 3] = [0x41, 0xff, 0xd3];
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

    // before entering jit, flush stdout buffer
    io::stdout().flush().unwrap_or_else(|_| eprintln!("failed to flush stdout"));

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
              : "rcx", "rbx", "rax", "r10", "r11", "r10", "r11"
              : "intel");
        
        result = (result_addr - base_memaddr) as usize;
        if PARAM.debug {
            eprintln!("returned at: {}", result);
        }
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

fn read_byte<'a>() -> Result<u8, &'a str> {
    let mut buf: [u8; 1] = [0];
    unsafe {
        let buf: *mut c_void = mem::transmute(&mut buf);
        if libc::read(0, buf, 1) == 0 {
            return Err("read failed")
        }
    }
    Ok(buf[0])
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

    fn compile(&self, is_function: bool) -> Asm {
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
            if is_function {
                sub.push(Asm::new(RET.to_vec()));
            }
            sub 
        }
    }
    fn countup(&mut self) {
        self.count += 1;
        match self.machine_code {
            Some(_) => (),
            None => {
                if PARAM.use_jit && self.count > PARAM.threshold {
                    let asm = self.compile(true);
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
                _ => (),
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
                        let asm = s.compile(false);
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
        Env{mem: [0; MEMSIZE], addr: INITIAL_MEM_ADDR}
    }

    fn page_size(size: usize) -> usize {
        let x = size % PAGESIZE;
        if x == 0 {
            size
        } else {
            size + PAGESIZE - (size % PAGESIZE)
        }
    }

    fn _dump(&self) {
        for i in self.addr - 10..self.addr+10 {
            print!("{} ", self.mem[i]);
        }
        println!();
    }

    fn run(&mut self, sub: &mut Sub, is_global: bool) -> Result<(), &str> {
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
                Op::Inc => self.mem[self.addr] = self.mem[self.addr].wrapping_add(1),
                Op::Dec => self.mem[self.addr] = self.mem[self.addr].wrapping_sub(1),
                Op::Out => {
                    let b: &[u8; 1] = &[self.mem[self.addr]];
                    match io::stdout().write(b) {
                        Ok(1) => (),
                        _ => return Err("stdin closed")
                    }
                },
                Op::In => {
                    match read_byte() {
                        Ok(x) => self.mem[self.addr] = x,
                        _ => return Err("stdin closed")
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
    let mut file = fs::File::open(&PARAM.filename)?;
    file.read_to_string(&mut buffer)?;

    match Op::parse(&mut buffer.chars(), true) {
        Ok(mut ops) => {
            let mut env = Env::new();
            match env.run(&mut ops, true) {
                Ok(_) => (),
                Err(s) => eprintln!("execution error: {}", s)
            }
        },
        Err(reason) => {
            eprintln!("parse error: {}", reason);
        }
    }
    Ok(())
}
