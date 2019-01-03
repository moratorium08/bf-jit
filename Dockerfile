FROM rustlang/rust:nightly

RUN groupadd -r user && useradd -r -g user user

COPY . /bf-jit-repo
WORKDIR /bf-jit-repo

RUN cargo build --release
RUN cp target/release/bf-jit /bf-jit

RUN chmod 555 /bf-jit
USER user

CMD ["/bin/sh"]
