# 3.19+: libbpf has bpf_dynptr and __ksym for 6.16+ probe_read_*_dynptr kfuncs.
FROM alpine:3.19

RUN apk add llvm clang libbpf-dev linux-headers
# alpine linux-headers install bpf.h as linux/bpf.h; the sources include <uapi/linux/bpf.h>
RUN mkdir -p /usr/include/uapi && ln -s ../linux /usr/include/uapi/linux

COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf

RUN clang -g -O2 -target bpf -D__KERNEL_FROM=618 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf618x86.o && llvm-strip --strip-debug ebpf618x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=618 -D__TARGET_ARCH_x86 -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf618x86cep.o && llvm-strip --strip-debug ebpf618x86cep.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=618 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf618arm64.o && llvm-strip --strip-debug ebpf618arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=618 -D__TARGET_ARCH_arm64 -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf618arm64cep.o && llvm-strip --strip-debug ebpf618arm64cep.o

RUN echo -en '// generated - do not edit\npackage ebpftracer\n\nvar ebpfProgs = map[string][]struct {\n' > ebpf.go \
	&& echo -en '\tversion string\n' >> ebpf.go \
	&& echo -en '\tflags   string\n' >> ebpf.go \
	&& echo -en '\tprog    []byte\n' >> ebpf.go \
	&& echo -en '}{\n' >> ebpf.go \
	&& echo -en '\t"amd64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"6.18", "ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf618x86cep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"6.18", "", []byte("' >> ebpf.go && gzip -c ebpf618x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '\t"arm64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"6.18", "ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf618arm64cep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"6.18", "", []byte("' >> ebpf.go && gzip -c ebpf618arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '}\n'>> ebpf.go
