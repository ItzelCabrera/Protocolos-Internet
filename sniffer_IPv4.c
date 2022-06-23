#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include<stdbool.h>
#include <netinet/ip.h>
#include<arpa/inet.h>
#include <sys/stat.h>
#include "FILA.h"

//Mascaras para obtener bits especificos
#define mask_pre 0xE0   //11100000b
#define mask_tos 0x1E   //00011110b
#define mask_mf 0x8000  //1000000000000000b
#define mask_df 0x4000  //0100000000000000b

//Estructuras para el sniffer
struct ifreq ifr;
struct sockaddr from;
struct ethhdr *eth;//leer la trama Ethernet II
struct iphdr *iph = NULL;//leer el datagrama IPv4
struct sockaddr_in source,dest; //almacena las direcciones IP destino y fuente


void *Analisis(); //función a realizar al crear el hilo
void *verificarAddr(char direccion[],int datagrams); //función a realizar al crear el hilo

int n_paquetes = 0;//número de paquetes a capturar
int datagrams = 0;
int protocolos[7]; 
__be16 ethertype;//para almacenar el tipo de protocolo de la capa superior de la trama capturada
char *buffer[2000]; //buffer para almacenar la subtrama capturada 
ssize_t size_bytes = 0;//bytes recibidos de la trama ethernet
char interfaz[20];//interfaz desde donde se configurara un modo promiscua
char tam_datagrams[5];
signed int header_length = 0;//var para medir la logitud de la cabecera
signed int total_length = 0;//var para medir a longitud totaldel datagrama (incluyendo cabecera)
unsigned int ID = 0; //id del datagrama
unsigned int ttl = 0; //tiempo de vida del datagrama
signed int useful_size = 0;//almacena la longitud de la carga útil del datagrama
unsigned int tos = 0;
unsigned int fragment;
int l_max = 50;
char caracteres[100];
int sx = 0;
int dx = 0;

//VAriables para el manejo de hilos
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;//acceso a RC
pthread_cond_t esperaCaptura = PTHREAD_COND_INITIALIZER; //var de condicion
pthread_cond_t esperaAnalisis = PTHREAD_COND_INITIALIZER; //var de condicion

int main(){
    FILE *f = fopen("RESUMEN.txt","w");
    Nodo *fila = NULL;//para llevar un control de las direcciones IP

	printf("Sniffer by Itzel Cabrera\n");
	printf("Introduce el número de paquetes a capturar : ");
	scanf("%d",&n_paquetes);
	printf("Introduce el nombre de la interfaz ethernet :");
	scanf("%s",interfaz); //eth0
    
	pthread_t hilo_analisis;
	if(pthread_create(&hilo_analisis,NULL,Analisis,NULL)){
	/*
	si pthread_create regresa un valor != 0 --> hubo un errror
	NULL--> es un joinable
	en el caso que sí se pueda crear el hilo, se ejecuta la funcion_hilo
	el argumento de la funcion se debe castear a void*
	*/
		printf("\nProblema en la creación del hilo\n");
		exit(EXIT_FAILURE);
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
            while(datagrams<n_paquetes){            
                size_bytes = recvfrom(id_socket,&buffer,2000,0,&from,&size_saddr);
                if(size_bytes != 1){
					pthread_mutex_lock(&mutex); 
					pthread_cond_signal(&esperaCaptura);
					pthread_cond_wait(&esperaAnalisis,&mutex); 
					pthread_mutex_unlock(&mutex); 
                }else {
                    printf("Error en los bytes recibidos");
                }       
            }//fin del while

           printf("%d ICMPv4 /   %d IGMP /   %d IP  /   %d TCP  /   %d UDP  /   %d IPv6 /   %d OSPF\n",protocolos[0],protocolos[1],protocolos[2],protocolos[3],protocolos[4],protocolos[5],protocolos[6]);
           printf("CLASIFICACIÓN SEGÚN EL TAMAÑO DEL DATAGRAMA\n");                       
           printf("0-159 bytes : %d datagramas\n",tam_datagrams[0]);
           printf("160-639 bytes : %d datagramas\n",tam_datagrams[1]);
           printf("640-1279 bytes : %d datagramas\n",tam_datagrams[2]);
           printf("1280-5119 bytes : %d datagramas\n",tam_datagrams[3]);
           printf(">5120 bytes : %d datagramas\n",tam_datagrams[4]);

           //Escribiendo el archivo del resumen
           fprintf(f,"%d ICMPv4 /   %d IGMP /   %d IP  /   %d TCP  /   %d UDP  /   %d IPv6 /   %d OSPF\n",protocolos[0],protocolos[1],protocolos[2],protocolos[3],protocolos[4],protocolos[5],protocolos[6]);
           fprintf(f,"CLASIFICACIÓN SEGÚN EL TAMAÑO DEL DATAGRAMA\n");                       
           fprintf(f,"0-159 bytes : %d datagramas\n",tam_datagrams[0]);
           fprintf(f,"160-639 bytes : %d datagramas\n",tam_datagrams[1]);
           fprintf(f,"640-1279 bytes : %d datagramas\n",tam_datagrams[2]);
           fprintf(f,"1280-5119 bytes : %d datagramas\n",tam_datagrams[3]);
           fprintf(f,">5120 bytes : %d datagramas\n",tam_datagrams[4]);
           Nodo *aux = fila;
            if(aux == NULL)printf("No existe ningun elemento\n");
            else{
                while(aux != NULL){
                    fprintf(f,"\nDireccion: %s",aux->direccion);
                    fprintf(f,"\t Sx: %d \t Dx: %d\n",aux->sx, aux->dx);
                    aux = aux->siguiente;
                }
            }
        }else printf("\nFallo en la reconfiguración de la NIC");
        
    }else printf("No se pudo crear de forma exitosa el socket raw");

	exit(EXIT_SUCCESS);
}

void *Analisis(){
    FILE *r = fopen("REGISTRO.txt","r+");
    if(r  == NULL) printf("ANALISIS FAIL \n");
	printf("\nEjecutando análisis del datagrama");
	while(datagrams<n_paquetes){ 
		pthread_mutex_lock(&mutex); 
		pthread_cond_wait(&esperaCaptura,&mutex);          
		eth = (struct ethhdr*)(buffer);
		ethertype = ntohs(eth->h_proto); //tipo de protocolo en la siguiente capa
		if(ethertype >= 0x0600){   
			if(ethertype == 0x0800){//IPv4
				printf("**********\n%d)Recepción exitosa datagrama IPv4\n",datagrams+1);   
				datagrams++;//se aumenta el contador de los datagramas
                iph = (struct iphdr*)(buffer);
                switch(iph->protocol){
                    case 0x01://ICMPv4
                        printf("Protocolo ICMPv4\n");
                        protocolos[0]++;
                        break;
                    case 0x02://IGMP
                        printf("Protocolo IGMP\n");
                        protocolos[1]++;
                        break;
                    case 0x04://IP
                        printf("Protocolo IP\n");
                        protocolos[2]++;
                        break;
                    case 0x06://TCP
                        printf("Protocolo TCP\n");
                        protocolos[3]++;
                        break;
                    case 0x11://UDP
                        printf("Protocolo UDP\n");
                        protocolos[4]++;
                        break;
                    case 0x29://IPv6
                        printf("Protocolo IPv6\n");
                        protocolos[5]++;
                        break;
                    case 0x59://OSPF
                        printf("Protocolo OSPF\n");
                        protocolos[6]++;                            
                        break;
                    default:
                        printf("Protocolo: Otro [%.2X]\n",iph->protocol);
                        break;

                }
				//Obtiene la dirección source
                memset(&source,0,sizeof(source));
                source.sin_addr.s_addr = iph->saddr;
                fflush(stdin);
				//Obtiene la dirección destino	
                memset(&dest,0,sizeof(dest));
                dest.sin_addr.s_addr = iph->daddr;
				//Obtiene la longitud de la cabecera
				header_length = ((signed int)iph->ihl)*4;//cada palabra es de 4 bytes
                //Obtiene la longitud total del datagrama
                total_length = ntohs(iph->tot_len);
                if(total_length<160){
                    tam_datagrams[0]++;
                }else if(total_length<640){
                    tam_datagrams[1]++;    
                }else if(total_length<1280){
                    tam_datagrams[2]++;
                }else if(total_length<5120){
                    tam_datagrams[3]++;
                }else{
                    tam_datagrams[4]++;
                }
                //Obtiene el ID del datagrama
                ID = ntohs(iph->id);                    
                //Obtiene el tiempo de vida
                ttl = (signed int)iph->ttl;
                //Obtiene la longitud de carga útil
                if((total_length-header_length)<0){//si solo se recibe 
                    useful_size = 0;
                }else{
                    useful_size = total_length-header_length;                    
                }
                //Obteniendo el tipo de servicio (8 bits)
                tos = iph->tos;
                printf("TOS ->  %.2X // ",tos);
                //Obteniendo los bits de precedencia
                switch(tos&mask_pre){
                    case 0x00:
                        printf("De rutina y ");
                        break;
                    case 0x20:
                        printf("Prioritario y ");
                        break;
                    case 0x40:
                        printf("Inmediato y ");
                        break;
                    case 0x60:
                        printf("Relámpago y ");
                        break;
                    case 0x80:
                        printf("Invalidación de relámpago y ");
                        break;
                    case 0xA0:
                        printf("Crítico y ");
                        break;
                    case 0xC0:
                        printf("Control de interred y ");
                        break;
                    case 0xE0:
                        printf("Control de red y ");
                        break;
                    default:
                        printf("Precedencia extraordinaria ");
                        break;
                }
                //Obteniendo los bits de tipo de servicio
                switch(tos&mask_tos){
                    case 0x08:
                        printf("minimiza el retardo\n");
                        break;
                    case 0x04:
                        printf("minimiza el rendimiento\n");
                        break;
                    case 0x02:
                        printf("minimiza la fiabilidad\n");
                        break;
                    case 0x01:
                        printf("minimiza el coste monetario\n");
                        break;
                    case 0x00:
                        printf("servicio normal\n");
                        break;
                    default:
                        printf(" y TOS extraordinario\n");
                        break;
                }
                fragment = iph->frag_off;
                //Obteniendo el bit de no fragmentación
                if(fragment&mask_df == 0x4000){//no se fragmentó 
                     printf("DF -> 1 => Datagrama no fragmentado\n");
                }else{//pudo haber sido fragmentado
                    printf("DF -> 0 => Datagrama fragmentado y ");
                    //Obteniendo el bit de más fragmentación
                    if(fragment&mask_mf == 0x8000){//no es el último fragmento (primero o intermedio)
                        if(fragment&0x1FFF == 0x0000){ //si MF es 1 y el desplazamiento es cero 
                            printf("es el primer datagrama\n");
                        }else{
                            printf("es un datagrama intermedio\n");            
                        }   
                    }else{//es el último o único fragmento (último o único)
                        if(fragment&0x1FFF == 0x0000){ //si MF es 0 y el desplazamiento es cero 
                            printf("es el único datagrama\n");
                        }else{
                            printf("es el último datagrama\n");            
                        }
                    }
                }
                printf("ID -> %d\n",ID);                    
                printf("Source IP -> %s\n",inet_ntoa(source.sin_addr));
                printf("Dest IP -> %s\n",inet_ntoa(dest.sin_addr));	
				printf("Header's length -> %d bytes\n",header_length);	
                printf("Total length -> %d bytes\n",total_length);	
                printf("TTL -> %d saltos\n",ttl);	
                printf("Useful Size -> %d bytes\n",useful_size);	

                //Análisis de las direcciones IP
                fila = insertarNuevoElemento(fila,inet_ntoa(source.sin_addr),1,0);
                fila = insertarNuevoElemento(fila,inet_ntoa(dest.sin_addr),0,1);
            } 
		}
        else{
			printf("Trama IEE 802.3, por lo tanto no puede ser analizada\n");
		}
		pthread_cond_signal(&esperaAnalisis);
		pthread_mutex_unlock(&mutex); 
	}//fin del while
}