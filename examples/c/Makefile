CFLAGS +=	-fsanitize=address

all:
	cbindgen ../.. > rules.h
	ac_cv_func_malloc_0_nonnull=yes \
	ac_cv_func_realloc_0_nonnull=yes \
		gcc $(CFLAGS) -o main main.c ../../target/debug/libsuricata_rule_parser.a -pthread -ldl -lm
