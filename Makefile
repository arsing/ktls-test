.PHONY: clean http openssl outdated print rustls test

openssl:
	cargo build --features openssl

clean:
	cargo clean

rustls:
	cargo build --features rustls

http:
	cargo build

outdated:
	cargo-outdated

print:
	git status --porcelain

test:
	cargo test --quiet --workspace

	cargo test --quiet --package ktls-test
	cargo test --quiet --package ktls-test --features openssl
	cargo test --quiet --package ktls-test --features rustls

	cargo clippy --workspace --tests --examples

	cargo clippy --package ktls-test --tests --examples
	cargo clippy --package ktls-test --features openssl --tests --examples
	cargo clippy --package ktls-test --features rustls --tests --examples
