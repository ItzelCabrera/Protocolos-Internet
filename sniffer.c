#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>

struct ifreq ifr;
struct sockaddr from;
struct ethhdr *eth;

void main(){
    __be16 ethertype;//para almacenar el tipo de protocolo de la capa superior de la trama capturada
    char *buffer[2000]; //buffer para almacenar la subtrama capturada 
    ssize_t size_bytes = 0;//bytes recibidos 
    FILE *file;//fichero para hacer el reporte
    unsigned char MAC_dest[6];//almacena los 6 bytes de la dirección MAC destino
    unsigned char MAC_source[6];//almacena los 6 bytes de la dirección MAC fuente
    long int useful_size = 0;//almacena la longitud de la carga útil de la trama capturada
    int cont = 0;//variable para determinar si es una difusión
    int frames[2];//[0]-> frames analizadas (Ethernet II) y [1]-> frames no analizadas(IEE 802.3)
    int protocolos[5]; //[0]-> IPv4 [1]-> IPv6 [2]-> ARP [3]-> CFE (control flujo ethernet) [4]-> Seguridad MAC
    int n_paquetes = 0;//número de paquetes a capturar
    char interfaz[20];//interfaz desde donde se configurara un modo promiscua
    char temp[20];

    file = fopen("Results.txt","w");
    if(file == NULL)printf("No se puede crear el archivo de texto\n");
    else {
        fprintf(file,"MAC destino\n");
        printf("Sniffer by Itzel Cabrera\n");
        printf("Introduce el número de paquetes a capturar : ");
        scanf("%d",&n_paquetes);
        printf("Introduce el nombre de la interfaz ethernet :");
        scanf("%s",interfaz); //eth0
    }
    int id_socket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));//retorna el id del socket raw
    if(id_socket != -1){
        printf("¡Socket creado de forma exitosa!");
        
        strncpy(ifr.ifr_name,interfaz,IFNAMSIZ);
        ioctl(id_socket,SIOCGIFFLAGS,&ifr);
        ifr.ifr_flags|=IFF_PROMISC;
        int v = ioctl(id_socket,SIOCSIFFLAGS,&ifr); //retorna una verificación de la reconfig exitosa de la NIC
        if(v != -1){
            printf("\nReconfiguración de la NIC de forma exitosa\n\n");  
            socklen_t size_saddr = sizeof(from);   //retorna el tamaño de la direccion del socket
            //printf("\nTamaño de la dirección del socket = %d",size_saddr); 
            while(frames[0]+frames[1]<n_paquetes){            
                size_bytes = recvfrom(id_socket,&buffer,2000,0,&from,&size_saddr);
                if(size_bytes != 1){
                    printf("****************************\n%d)Recepción exitosa de %ld bytes\n",frames[0]+frames[1]+1,size_bytes);   
                    eth = (struct ethhdr*)(buffer);
                    ethertype = ntohs(eth->h_proto); //tipo de protocolo en la siguiente capa
                    if(ethertype >= 0x0600){
                        printf("Trama Ethernet II\n");     
                        frames[0]++;//se aumenta el contador de los frames tipo IEthernet II
                        //printf("Protocolo : %x \n",ethertype);
                        switch(ethertype){
                            case 0x0800:
                                printf("Protocolo: IPv4\n");
                                protocolos[0]++;
                                break;
                            case 0x86DD:
                                printf("Protocolo: IPv6\n");
                                protocolos[1]++;
                                break;
                            case 0x0806:
                                printf("Protocolo: ARP\n");
                                protocolos[2]++;
                                break;
                            case 0x8808:
                                printf("Protocolo: Control de flujo Ethernet\n");
                                protocolos[3]++;
                                break;
                            case 0x88E5:
                                printf("Protocolo: Seguridad MAC\n");
                                protocolos[4]++;
                                break;
                            default:
                                printf("Otro");
                                break;
                        }  
                        printf("MAC destino: ");
                        for (int j = 0;j<6;j++){
                            MAC_dest[j] = eth->h_dest[j]; //Direccion MAC destino
                            MAC_source[j] = eth->h_source[j];   //Dirección MAC fuente 
                            printf("%.2X-",MAC_dest[j]);     
                            if(MAC_dest[j] == 0xFF)cont++;  
                            if(j == 5){
                                if(cont == 6)printf("> Difusion\n");
                                else if(MAC_dest[5]%2 == 0)printf("> Unidifusion\n"); //par->unidifusion
                                else  printf("> Multidifusion\n"); //impar-> multidifusion
                            } 
                        }
                        //Longitud de la trama recibida = size_bytes
                        //Longitud de carga útil
                        useful_size = size_bytes - 14; //se restan los 6 bytes de cada direcciones y los 2 de longitud/tipo
                        fprintf(file,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",MAC_dest[0],MAC_dest[1],MAC_dest[2],MAC_dest[3],MAC_dest[4],MAC_dest[5]); 
                    }else {
                        printf("Trama IEE 802.3, por lo tanto no puede ser analizada\n");
                        frames[1]++; //se aumenta el contador de los frames tipo IEE 802.3
                    }
                }else {
                    printf("Error en los bytes recibidos");
                    //fflush(stdin);
                }
                cont = 0;  //resetea para volver a contar el número de xFF en las direcciones MAC de la nueva trama capturada                
            }//fin del while
            printf("\nSe analizaron %d tramas: %d fueron Ethernet II y %d fueron IEE 802.3\n",frames[0]+frames[1],frames[0],frames[1]);
            printf("%d IPv4 /   %d IPv6 /   %d ARP  /   %d Control de flujo de Ethernet  /   %d Seguridad MAC.",protocolos[0],protocolos[1],protocolos[2],protocolos[3],protocolos[4]);
            fprintf(file,"****************************\n");            
            fprintf(file,"Se analizaron %d tramas, %d Ethernet II y %d IEEE 802.3 \n",n_paquetes,frames[0],frames[1]);
            fprintf(file,"****************************\n");  
            fprintf(file,"Distribución de los protocolos: %d IPv4 /   %d IPv6 /   %d ARP  /   %d Control de flujo de Ethernet  /   %d Seguridad MAC.\n",protocolos[0],protocolos[1],protocolos[2],protocolos[3],protocolos[4]);
        }else printf("\nFallo en la reconfiguración de la NIC");
        
    }else printf("No se pudo crear de forma exitosa el socket raw");
}

