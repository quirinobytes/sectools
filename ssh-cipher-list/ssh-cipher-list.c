/*
 *  * NL- SSH2 Ciphers List v1.0
 *   * Listagem de cifras permitidas em um servidor SSH.
 *    *
 *     * Autor: Glaudson Ocampos aka Nash Leon
 *      * glaudson@securitylabs.com.br
 *       * nashleon2.0@gmail.com
 *        *
 *         * Janeiro de 2014.
 *          */

/*
 *  * Precisamos da libssh2 - http://www.libssh2.org/
 *   * Compile com:
 *    * # gcc -o NL-ssh2_cipher_list NL-ssh2_cipher_list.c -lssh2 -Wall
 *     *
 *      * Uso:
 *       * # ./NL-ssh2_cipher_list 
 *        * NL-SSH Ciphers List - 1.0
 *         * Uso: ./NL-ssh2_cipher_list <host> <porta>
 *          * # ./NL-ssh2_cipher_list 192.168.1.111 22
 *           * Sessao estabelecida!
 *            * Algoritmo permitido: aes128-ctr.
 *             * Algoritmo permitido: aes192-ctr.
 *              * Algoritmo permitido: aes256-ctr.
 *               * Algoritmo nao permitido:arcfour256.
 *                * Algoritmo permitido: arcfour128.
 *                 * Algoritmo permitido: aes128-cbc.
 *                  * Algoritmo permitido: 3des-cbc.
 *                   * Algoritmo permitido: blowfish-cbc.
 *                    * Algoritmo permitido: cast128-cbc.
 *                     * Algoritmo permitido: aes192-cbc.
 *                      * Algoritmo permitido: aes256-cbc.
 *                       * Algoritmo permitido: arcfour.
 *                        * Algoritmo nao permitido:none.
 *                         * Listagem terminada.
 *                          *
 *                           */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libssh2.h>

#define         VERSAO          "1.0"
#define         ERRO            -1
#define         USERNAME        "root"
#define         PASSWORD        "password"


char *cifras[] = { "aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128",
                   "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes192-cbc",
                   "aes256-cbc", "arcfour", "none"};


void
_uso(char *progname){
    fprintf(stdout,"NL-SSH Ciphers List - %s\n", VERSAO);
    fprintf(stdout,"Uso: %s <host> <porta>\n\n", progname);
    _exit(0);
}

int 
main(int argc, char *argv[]){
    unsigned long hostaddr;
    int rc, sock;
    struct sockaddr_in sin;
    unsigned int porta=22, i=0;
    unsigned int total_cifras = 0;

    LIBSSH2_SESSION *session;

    if(argc < 2){
       _uso(argv[0]);
    }

    hostaddr = inet_addr(argv[1]);

    if(argc > 2) porta = atoi(argv[2]);

    rc = libssh2_init (0);
    if (rc != 0) {
        fprintf (stderr, "falha em inicializar a libssh2(%d).\n", rc);
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(porta);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Falha na conexao!\n");
        return ERRO;
    }

    session = libssh2_session_init();

    if (libssh2_session_handshake(session, sock)) {
      fprintf(stderr, "Falha em estabelecer sessao.\n");
      return -1;
    }
    else {
       fprintf(stdout,"Sessao estabelecida!\n");
       fflush(stdout);  
    } 

   total_cifras = sizeof(cifras)/sizeof(cifras[0]);

   for(i = 0; i < total_cifras; i++){
        if(cifras[i] == NULL) break;
        if(libssh2_session_method_pref(session,LIBSSH2_METHOD_CRYPT_CS,cifras[i])) {
                fprintf(stderr, "Algoritmo nao permitido:%s.\n", cifras[i]);
                fflush(stderr);
        }
        else {
                fprintf(stdout,"Algoritmo permitido: %s.\n",cifras[i]);
                fflush(stderr);
        }
    }

    libssh2_session_disconnect(session,"Sessao finalizada.");
    libssh2_session_free(session);

    close(sock);
    libssh2_exit();

    fprintf(stdout,"Listagem terminada.\n");
    fflush(stdout);
    return 0;
}
