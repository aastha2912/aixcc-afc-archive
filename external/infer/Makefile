BIN = infer
SYMLINKS = infer-analyze infer-capture infer-compile infer-debug \
	infer-explore infer-help infer-report infer-reportdiff infer-run

local: $(BIN) lib clang symlinks

#docker:
#	@echo "Building docker"
#	docker build -t infer_build .

docker:
	#docker pull ghcr.io/theori-io/crs:$(TAG:-latest)
	true

$(BIN): docker
	mkdir -p infer/bin
	@echo "Copying out infer"
	docker run --rm -v "$(shell pwd):/output" infer_build cp /infer/infer/bin/infer /output/infer/bin/

lib: docker
	mkdir -p infer/lib
	@echo "Copying out infer"
	docker run --rm -v "$(shell pwd):/output" infer_build cp -r /infer/infer/lib /output/infer/

clang: docker
	@echo "Copying out clang plugins"
	docker run --rm -v "$(shell pwd):/output" infer_build rsync -a --exclude 'clang/src' /infer/facebook-clang-plugins/ /output/facebook-clang-plugins/

symlinks: $(SYMLINKS)

$(SYMLINKS): %: #$(BIN)
	ln -sf $(BIN) infer/bin/$@

clean:
	@rm -rf infer facebook-clang-plugins
	@echo "Cleaned up"
