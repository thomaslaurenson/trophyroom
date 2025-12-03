MDBOOK_VERSION = "v0.5.1"

install_mdbook:
	curl -L "https://github.com/rust-lang/mdBook/releases/download/$(MDBOOK_VERSION)/mdbook-$(MDBOOK_VERSION)-x86_64-unknown-linux-gnu.tar.gz" | tar -xz

run:
	./mdbook serve

clean:
	./mdbook clean

build:
	./mdbook build

build_and_serve:
	./mdbook build && ./mdbook serve
