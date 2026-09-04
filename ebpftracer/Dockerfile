# CO-RE objects. They translate PIDs into the namespace of the agent (see ebpf/pidns.h),
# which requires the running kernel to expose its own BTF, so they are only used when
# /sys/kernel/btf/vmlinux is present and the plain objects below stay as the fallback.
#
# Built on a newer Alpine because the CO-RE relocation builtins these objects rely on
# (__builtin_preserve_type_info and friends) are not available in the clang shipped with
# alpine:3.14. The plain objects keep using the old toolchain so that they come out of
# this build unchanged.
#
# Not built for 4.x: bpf_probe_read_kernel() and .rodata constants need 5.5+.
FROM alpine:3.19 AS core

RUN apk add llvm clang libbpf-dev linux-headers

COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf

RUN clang -g -O2 -target bpf -I/usr/include/bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_x86 -D__CORE_PIDNS -c ebpf.c -o ebpf506x86core.o && llvm-strip --strip-debug ebpf506x86core.o
RUN clang -g -O2 -target bpf -I/usr/include/bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -D__CORE_PIDNS -c ebpf.c -o ebpf512x86core.o && llvm-strip --strip-debug ebpf512x86core.o
RUN clang -g -O2 -target bpf -I/usr/include/bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -D__CORE_PIDNS -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf512x86corecep.o && llvm-strip --strip-debug ebpf512x86corecep.o
RUN clang -g -O2 -target bpf -I/usr/include/bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_arm64 -D__CORE_PIDNS -c ebpf.c -o ebpf506arm64core.o && llvm-strip --strip-debug ebpf506arm64core.o
RUN clang -g -O2 -target bpf -I/usr/include/bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -D__CORE_PIDNS -c ebpf.c -o ebpf512arm64core.o && llvm-strip --strip-debug ebpf512arm64core.o
RUN clang -g -O2 -target bpf -I/usr/include/bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -D__CORE_PIDNS -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf512arm64corecep.o && llvm-strip --strip-debug ebpf512arm64corecep.o

FROM alpine:3.14

RUN apk add llvm clang libbpf-dev linux-headers

COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf

RUN clang -g -O2 -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf416x86.o && llvm-strip --strip-debug ebpf416x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf420x86.o && llvm-strip --strip-debug ebpf420x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf506x86.o && llvm-strip --strip-debug ebpf506x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf512x86.o && llvm-strip --strip-debug ebpf512x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf512x86cep.o && llvm-strip --strip-debug ebpf512x86cep.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf416arm64.o && llvm-strip --strip-debug ebpf416arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf420arm64.o && llvm-strip --strip-debug ebpf420arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf506arm64.o && llvm-strip --strip-debug ebpf506arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf512arm64.o && llvm-strip --strip-debug ebpf512arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf512arm64cep.o && llvm-strip --strip-debug ebpf512arm64cep.o

COPY --from=core /tmp/ebpf/ebpf506x86core.o /tmp/ebpf/ebpf512x86core.o /tmp/ebpf/ebpf512x86corecep.o /tmp/ebpf/
COPY --from=core /tmp/ebpf/ebpf506arm64core.o /tmp/ebpf/ebpf512arm64core.o /tmp/ebpf/ebpf512arm64corecep.o /tmp/ebpf/

RUN echo -en '// generated - do not edit\npackage ebpftracer\n\nvar ebpfProgs = map[string][]ebpfProg{\n' > ebpf.go \
	&& echo -en '\t"amd64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "core,ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf512x86corecep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "core", []byte("' >> ebpf.go && gzip -c ebpf512x86core.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.6", "core", []byte("' >> ebpf.go && gzip -c ebpf506x86core.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf512x86cep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "", []byte("' >> ebpf.go && gzip -c ebpf512x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.6", "", []byte("' >> ebpf.go && gzip -c ebpf506x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.20", "", []byte("' >> ebpf.go && gzip -c ebpf420x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.16", "", []byte("' >> ebpf.go && gzip -c ebpf416x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '\t"arm64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "core,ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf512arm64corecep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "core", []byte("' >> ebpf.go && gzip -c ebpf512arm64core.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.6", "core", []byte("' >> ebpf.go && gzip -c ebpf506arm64core.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf512arm64cep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "", []byte("' >> ebpf.go && gzip -c ebpf512arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.6", "", []byte("' >> ebpf.go && gzip -c ebpf506arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.20", "", []byte("' >> ebpf.go && gzip -c ebpf420arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.16", "", []byte("' >> ebpf.go && gzip -c ebpf416arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '}\n'>> ebpf.go
