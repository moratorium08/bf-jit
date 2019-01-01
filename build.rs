extern crate gcc;

fn main() {
    gcc::Config::new()
        .file("src/libbf.s")
        .include("src")
        .compile("libbf.a");
}
