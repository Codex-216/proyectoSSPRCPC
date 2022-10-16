package com.sniffer;


import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Scanner;

public class packet {
    private final String data[];
    private int sizePacket;
    
    public packet(){
        data = new String[500];
        sizePacket = 0;
    }
    
    public void readDataFile(File file){
        try {
            Scanner sc = new Scanner(file);
            String aux = null;
            
            while (sc.hasNextLine()){
                aux =  sc.nextLine();

                String[] resultSplit  = aux.split("\\s+");

                for(int x = 1; x < resultSplit.length; x++){
                    data[sizePacket] = resultSplit[x];
                    sizePacket++;
                }
        
            } 
        } catch (IOException e) {
            e.printStackTrace();
        }  
    }
    
    public String[] getData(){
        return data;
    }
    
    /**
     *
     * @return
     */
    @Override
    public String toString(){
        int aux = sizePacket / 16 + 1;
        int cont = 0;
        String aux2 = "";
        

        for(int x = 0; x < aux; x++){
            aux2 += "000" + x +"  ";
            for(int y = 0; y < 16; y++){
                aux2 += data[cont] + "  ";
                cont++;
                
                if(cont == sizePacket)
                    break;
            }
            aux2 += "\n";

        }
        
        return aux2;
    }
    
    public int getsizePacket(){
        return sizePacket;
    }
    
    
    // Funciones obtencion de datos Trama Ethernet
    public String getDestMAC(){
        String aux = "";
        
        for(int x = 0; x <= 5; x++){
            aux += data[x];
            if(x < 5)
                aux += ":";
        }
        
        return aux;
    }
    
    public String getSourceMAC(){
        String aux = "";
        
        for(int x = 6; x <= 11; x++){
            aux += data[x];
            if(x < 11)
                aux += ":";
        }
        
        return aux;
    }
    
    public String getProtocolType(){
        String aux = getPartOfData(data, 12, 13);
        
        return "0x" + aux + " - " + getProtocol(aux);
    }
    
    public String getVersion(){
        String aux = data[14];
        
        return "0x" + aux.substring(0,1)  +  " - " + aux.substring(0,1);
    }
    
    public String getLenghtHeader(){
        String aux = data[14];
        
        return  "0x" + aux.substring(1,2)  +  " - " + String.valueOf(Integer.parseInt( aux.substring(0,1)) * Integer.parseInt( aux.substring(1,2)));
    }
    
    public String getPrecedencia(){
        String aux = convertHexToBinary(data[15]);

        return "0b" + aux.substring(0,3) + " - " + getValuePrecedence(aux.substring(0,3));
    }
    
    public String getServiceType(){
        String aux = convertHexToBinary(data[15]);

        return "0b" + aux.substring(3,7) + " - " + getValueServiceType(aux.substring(3,7));
    }
    
    public String getMBZ(){
        String aux = convertHexToBinary(data[15]);

        return "0b" + aux.substring(7) +  " - " + "Valor por defecto = 0";
    }
    
    public String getLongitudTotalPaquete(){
        String aux = data[16] + data[17];
        String aux2 = convertHexToBinary(aux);
        aux2 = convertBinarytoDecimal(aux2);
        
        return "0x" + aux + " - " +  aux2 + " bytes";
    }
    
    public String getIdentification(){
        String aux = data[18] + data[19];
        
        return "0x" + aux ;
    }
    
    public String getBF(){
        String aux = data[20];
        aux = convertHexToBinary(aux);
        
        aux = aux.substring(2, 3);

        return "0b" + aux + " - " + "Reservado para ser Cero";
    } 
    
    public String getDF(){
        String aux = data[20];
        String aux2 = "";
        aux = convertHexToBinary(aux);
        
        aux = aux.substring(1, 2);
        
        if("0".equals(aux))
            aux2 = "Permite Fragmentar";
        else if("1".equals(aux))
            aux2 = "No Permite Fragmentar";
        
        return "0b" + aux + " - " + aux2;
    } 
    
    public String getMB(){
        String aux = data[20];
        String aux2 = "";
        aux = convertHexToBinary(aux);
        
        aux = aux.substring(0, 1);
        
        if("0".equals(aux))
            aux2 = "Ultimo Fragmento";
        else if("1".equals(aux))
            aux2 = "NO es el Ultimo Fragmento";
        
        return "0b" + aux + " - " + aux2;
    } 
    
    public String getDesplazamientoFragmentacion(){
        String aux = data[20] + data[21];
        aux = convertHexToBinary(aux);
        
        return "0b" + aux.substring(3);
    }
    
    public String getTTL(){
        String aux = data[22];
        String aux2 = convertHexToBinary(aux);
        aux2 = convertBinarytoDecimal(aux2);
        
        return "0x" + aux + " - " + aux2 + " Segundos";
    }
    
    public String getProtocolAltoNivel(){
        String aux = data[23];
        String aux2 = convertHexToBinary(aux);
        aux2 = convertBinarytoDecimal(aux2);
        
        if("06".equals(aux))
            aux2 = "TCP";
        else
            aux2 = "Error: No se encontro el protocolo";
        
        return "0x" + aux + " - " + aux2;
    }
    
    public String getChecksum(){
        String value1 = "";
        String value2 = "";
        String sum = "";
        String valorChecksumOriginal = "";
        String valorChecksumObtenido = "";

        //Obtenemos los dos primeros valores del paquete que vamos a sumar
        value1 = data[14] + data[15];
        value2 = data[16] + data[17]; 
        
        //Los convertimos a binario
        value1 = convertHexToBinary(value1);
        value2 = convertHexToBinary(value2);
        
        //Obtenemos el complemento A!
	value1 = getComplementA1(value1);
	value2 = getComplementA1(value2);
        
        //realizamos la suma
        sum = sumBinary(value1, value2);
        
        
        //Ahora comenzaremso a realizar las sumas sin tomar en cuenta el dato
        //24 y 25 que son los valores del cheksum que vamos a compara
        for(int x = 18; x <= 33; x+=2){
            if(x != 24){
                value1 = data[x] + data[x + 1];
                value1 = convertHexToBinary(value1);
                value1 = getComplementA1(value1);
                sum = sumBinary(value1, sum);
                 
            } 
        }
        
        valorChecksumOriginal = data[24] + data[25];
        valorChecksumObtenido = convertBinaryToHex(sum);
        
        if(valorChecksumOriginal.equals(valorChecksumObtenido))
            return "0x" + valorChecksumObtenido + " - " + " Sin errores";
        else
            return "0x" + valorChecksumObtenido + " - " + " Con errores";
   
    }
      
    public String getIPOrigen(){
        String hex = data[26] + data[27] + data[28] + data[29];
        String aux = null;
        aux = convertBinarytoDecimal(convertHexToBinary(data[26]));
        aux += ".";
        aux += convertBinarytoDecimal(convertHexToBinary(data[27]));
        aux += ".";
        aux += convertBinarytoDecimal(convertHexToBinary(data[28]));
        aux += ".";
        aux += convertBinarytoDecimal(convertHexToBinary(data[29]));
        
        return "0x" + hex + " - " + aux;
    }
    
    public String getIPDestino(){
        
        String hex = data[30] + data[31] + data[32] + data[33];
        String aux = null;
        aux = convertBinarytoDecimal(convertHexToBinary(data[30]));
        aux += ".";
        aux += convertBinarytoDecimal(convertHexToBinary(data[31]));
        aux += ".";
        aux += convertBinarytoDecimal(convertHexToBinary(data[32]));
        aux += ".";
        aux += convertBinarytoDecimal(convertHexToBinary(data[33]));
        
        return "0x" + hex + " - " + aux;
 
    }
    
    // Funciones Pseudo-Cabecera TCP
    
    private String getIPOrigenPseudo(){
        return data[26] + data[27] + data[28] + data[29];
    }
    
    private String getIPDestinoPseudo(){
        return data[30] + data[31] + data[32] + data[33];
    }
    
    private String getTipoProtocoloPseudo(){
        return data[23];
    }
    
    private String getTamanoCabeceraTCPPseudo(){
        // Tamano total paquete - tamaño IPv4 - tamaño Ethernet
        int size = getsizePacket() - 20 - 18;
        String result = "004C";
        return result;
    }
    
    
    // --------------- Funciones TCP ------------------------
    
    public String getSourcePort(){
        String hex = data[34] + data [35];
        String value = convertHexToDecimal(hex);
        
        String portName = "Desconocido";
        
        if("53".equals(value)){
            portName = "DNS";
        }
        
        if("1031".equals(value)){
            portName = "FTP Asociado";
        }
        
        
        return "0x" + hex + " - " + value + " - " + portName;
    }
    
    public String getDestinationPort(){
        String hex = data[36] + data [37];
        String value = convertHexToDecimal(hex);
        
        String portName = "Desconocido";
        
        if("50100".equals(value)){
            portName = "Dinamico";
        }
        
        if("139".equals(value)){
            portName = "NetBIOS SS";
        }
        
        
        return "0x" + hex + " - " + value + " - " + portName;
    }
    
    public String getSequenceNumber(){
        String hex = data[38] + data [39] + data[40] + data [41];
        String value = convertHexToDecimal(hex);
        
        
        return "0x" + hex + " - " + value;
    }
    
    public String getAckNumber(){
        String hex = data[42] + data [43] + data[44] + data [45];
        String value = convertHexToDecimal(hex);
        
        
        return "0x" + hex + " - " + value;
    }
    
    
    public String getLenght_Header(){
        String hex = data[46];
        String binary = "";
        int lenght = 0;
        
        binary = convertHexToBinary(hex);
        binary = binary.substring(0, 4);
        
        // Multiplicar el numero de renglones por el numero de bytes de cada renglon
        lenght = Integer.valueOf(convertBinarytoDecimal(binary)) * 4;

                
        return "0b" + binary + " - " + lenght + " bytes";
    }
    
    public String Reserved(){
        String hex = data[46];
        String binary = "";
          

        binary = convertHexToBinary(hex);
        binary = binary.substring(4, 7);
                
        return "0b" + binary + " - "  + " Reservado Cero";
    }
    
    public String NS_flag(){
        String hex = data[46];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(7, 8);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String CWR_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(0, 1);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String ECE_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(1, 2);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String URG_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(2, 3);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String ACK_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(3, 4);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String PSH_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(4, 5);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String RST_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(5, 6);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String SYN_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";

        binary = convertHexToBinary(hex);
        binary = binary.substring(6, 7);
        
        if("1".equals(binary)){
            status = "Activado";
        }

        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String FIN_flag(){
        String hex = data[47];
        String binary = "";
        String status = "Desactivado";
        
        binary = convertHexToBinary(hex);
        binary = binary.substring(7, 8);
        
        if("1".equals(binary)){
            status = "Activado";
        }
                
        return "0b" + binary + " - "  + binary + " " + status;
    }
    
    public String getWindowSize(){
        String hex = data[48] + data[49];
     
        return "0x" + hex + " - " + convertHexToBinary(hex);
    }
    
    public String getChecksumTCP(){ 
        
        String aux = "";
        String result = "";
        String pseudocabecera[] = new String [6];
        String value1 = "";
        String value2 = "";
        // Un arreglo para cada resultado (pseudocabecera, tcp , datos y la suma totoal)
        String sum[] = new String[4];
        
      
        // #########################################################################
        
        // Pseudocabecera
        
        // Armamos la pseudocabecera
        aux = getIPOrigenPseudo();
        aux += getIPDestinoPseudo();
        aux += "00";
        aux += getTipoProtocoloPseudo();
        aux += getTamanoCabeceraTCPPseudo();
        
        aux = convertHexToBinary(aux);
                
        pseudocabecera[0] = aux.substring(0, 16);
        pseudocabecera[1] = aux.substring(16, 32);
        pseudocabecera[2] = aux.substring(32, 48);
        pseudocabecera[3] = aux.substring(48, 64);
        pseudocabecera[4] = aux.substring(64, 80);
        pseudocabecera[5] = aux.substring(80, 96);
        
        // Obtenemos complemento A1 y realizamos la suma
        for(int x = 0; x < 6; x++){
            pseudocabecera[x] = getComplementA1(pseudocabecera[x]);
        }
        
        sum[0] = sumBinary(pseudocabecera[0], pseudocabecera[1]);
        sum[0] = sumBinary(sum[0], pseudocabecera[2]);
        sum[0] = sumBinary(sum[0], pseudocabecera[3]);
        sum[0] = sumBinary(sum[0], pseudocabecera[4]);
        sum[0] = sumBinary(sum[0], pseudocabecera[5]);
        System.out.println("--------- PseudoCabecera ------------");
        System.out.println("Suma (Sin complemento) = " + sum[0]);
        System.out.println("Suma (Sin complemento) = " + convertBinaryToHex(sum[0]));
        // Guardamos el resultado de la suma en el arreglo en la posicion 0
        sum[0] = getComplementA1(sum[0]);
        System.out.println("Suma (Con complemento) = " + sum[0]);
        System.out.println("Suma (Con complemento) = " + convertBinaryToHex(sum[0]));
        // #########################################################################
        
        // Cabecera TCP 34 - 53
        
        //Obtenemos los dos primeros valores del paquete que vamos a sumar
        value1 = data[34] + data[35];
        value2 = data[36] + data[37]; 
        
        //Los convertimos a binario
        value1 = convertHexToBinary(value1);
        value2 = convertHexToBinary(value2);
        
        //Obtenemos el complemento A!
	value1 = getComplementA1(value1);
	value2 = getComplementA1(value2);
        
        //realizamos la suma
        sum[1] = sumBinary(value1, value2);
        
        //Ahora comenzaremso a realizar las sumas sin tomar en cuenta el dato
        //50 y 51 que son los valores del cheksum que vamos a compara
        for(int x = 38; x <= 53; x+=2){
            if(x != 50){
                value1 = data[x] + data[x + 1];
                value1 = convertHexToBinary(value1);
                value1 = getComplementA1(value1);
                sum[1] = sumBinary(value1, sum[1]);
                 
            } 
        }
        
        System.out.println("---------       TCP      ------------");
        System.out.println("Suma (Sin complemento) = " + sum[1]);
        System.out.println("Suma (Sin complemento) = " + convertBinaryToHex(sum[1]));
        
        // Guardamos el valor de suma en el arreglo en la posicion 1
        sum[1] = getComplementA1(sum[1]);
        
        System.out.println("Suma (Con complemento) = " + sum[1]);
        System.out.println("Suma (Con complemento) = " + convertBinaryToHex(sum[1]));
        // #########################################################################
        
        // Cabecera Datos 
        
        //Obtenemos los dos primeros valores del paquete que vamos a sumar
        value1 = data[54] + data[55];
        value2 = data[56] + data[57]; 
        
        //Los convertimos a binario
        value1 = convertHexToBinary(value1);
        value2 = convertHexToBinary(value2);
        
        //Obtenemos el complemento A!
	value1 = getComplementA1(value1);
	value2 = getComplementA1(value2);
        
        //realizamos la suma
        sum[2] = sumBinary(value1, value2);
        
        //Ahora comenzaremso a realizar las sumas 
        for(int x = 58; x <= 109; x+=2){
            value1 = data[x] + data[x + 1];
            value1 = convertHexToBinary(value1);
            value1 = getComplementA1(value1);
            sum[2] = sumBinary(value1, sum[2]);
        }
        
        System.out.println("---------      Datos     ------------");
        System.out.println("Suma (Sin complemento) = " + sum[2]);
        System.out.println("Suma (Sin complemento) = " + convertBinaryToHex(sum[2]));
        
        // Guardamos el valor de suma en el arreglo en la posicion 1
        sum[2] = getComplementA1(sum[2]);
        
        System.out.println("Suma (Con complemento) = " + sum[2]);
        System.out.println("Suma (Con complemento) = " + convertBinaryToHex(sum[2]));
        
                
        // #########################################################################
        
        // Suma final de los complementos de los demas resultados 
                
        sum[3] = sumBinary(sum[0], sum[1]);
        sum[3] = sumBinary(sum[3], sum[2]);

        result = getComplementA1(sum[3]);
        result = convertBinaryToHex(result);
                
                
         String hex = data[50] + data[51];
        return "0x" + hex + " - " + result;       
                
      
                
                
                
                
                
                
                
                
                
                
                
                
                
                
                
                
        /*
        valorChecksumOriginal = data[24] + data[25];
        valorChecksumObtenido = convertBinaryToHex(sum);
        
        if(valorChecksumOriginal.equals(valorChecksumObtenido))
            return "0x" + valorChecksumObtenido + " - " + " Sin errores";
        else
            return "0x" + valorChecksumObtenido + " - " + " Con errores";
        */
        
        
        
        
        
        
        
        // Primer paso, armamos la Pseudocabecera
        
        
        /*

        String sum;
        String value1;
        String value2;
        String value3;
        String value4;
        String value5;
        String value6;
        //Los convertimos a binario
        value1 = "1010100010110000";
        value2 = "0000001101101100";
        value3 = "1010100010110000";
        value4 = "0000001100011001";
        value5 = "0000000000000110";
        value6 = "0000000000011100";
        
        //Obtenemos el complemento A!
	/*
        value1 = getComplementA1(value1);
	value2 = getComplementA1(value2);
        value3 = getComplementA1(value3);
        value4 = getComplementA1(value4);
        value5 = getComplementA1(value5);
        value6 = getComplementA1(value6);
        */
        
        //realizamos la suma
        /*
        sum = sumBinary(value1, value2);
        sum = sumBinary(sum, value3);
        sum = sumBinary(sum, value4);
        sum = sumBinary(sum, value5);
        sum = sumBinary(sum, value6);
        
        
        return sum;
        */
        
        
        // ############################################
        
        /*
        String value1 = "0000010110010011";
        String value2 = "0000000000010101";
        String value3 = "0000000010001010";
        String value4 = "1100101010011011";
        String value5 = "0000000000000000";
        String value6 = "0000000000000000";
        String value7 = "0111000000000010";
        String value8 = "0010000000000000";
        String value9 = "0000000000000000";
        String value10 = "0000000000000000";
        String value11 = "0000001000000100";
        String value12 = "0000001000011000";
        String value13 = "0000000100000001";
        String value14 = "0000010000000010";
        String sum = "";
        
        value1 = getComplementA1(value1);
	value2 = getComplementA1(value2);
        value3 = getComplementA1(value3);
        value4 = getComplementA1(value4);
        value5 = getComplementA1(value5);
        value6 = getComplementA1(value6);
        value7 = getComplementA1(value7);
	value8 = getComplementA1(value8);
        value9 = getComplementA1(value9);
        value10 = getComplementA1(value10);
        value11= getComplementA1(value11);
        value12 = getComplementA1(value12);
        value13 = getComplementA1(value13);
        value14 = getComplementA1(value14);
        
        
        sum = sumBinary(value1, value2);
        sum = sumBinary(sum, value3);
        sum = sumBinary(sum, value4);
        sum = sumBinary(sum, value5);
        sum = sumBinary(sum, value6);
        sum = sumBinary(sum, value7);
        sum = sumBinary(sum, value8);
        sum = sumBinary(sum, value9);
        sum = sumBinary(sum, value10);
        sum = sumBinary(sum, value11);
        sum = sumBinary(sum, value12);
        sum = sumBinary(sum, value13);
        sum = sumBinary(sum, value14);

        sum = getComplementA1(sum);

        
        String result = sumBinary(sum,"0101100000001000");
 
        result = getComplementA1(result);

        result = convertBinaryToHex(result);
        
        */
        
    }
    
    public String getUrgPointer(){
        String hex = data[52] + data[53];
        
        return "0x" + hex + " - " + convertHexToDecimal(hex);
    }
    
    // --------------- Funciones Auxiliares ----------------
    
    public String getValuePrecedence(String value){
        if("000".equals(value))
            return "Rutina";
        if("001".equals(value))
            return "Prioridad";
        if("010".equals(value))
            return "Inmediato";
        if("011".equals(value))
            return "Flash";
        if("100".equals(value))
            return "Flash Override";
        if("101".equals(value))
            return "Critico";
        if("110".equals(value))
            return "Contorl de red (InterNetwork Control)";
        if("111".equals(value))
            return "Contorl de red (Network Control)";
        
        return "Error - No se pudo obtener el tipo de precedencia";
    }
    
    public String getValueServiceType(String value){
        if("1000".equals(value))
            return "Minimizar Retardo";
        if("0100".equals(value))
            return "Maximizar la densidad de flujo";
        if("0010".equals(value))
            return "Maximizar la Fiabilidad";
        if("0001".equals(value))
            return "Minimizar el Coste Monetario";
        if("0000".equals(value))
            return "Servicio Normal";
        
        return "Error - No se pudo obtener el tipo de servicio";
    }
    
    public String getProtocol(String hex){
             
        if("0800".equals(hex))
            return "IPv4";
        if("0806".equals(hex))
            return "Address Resolution Protocol (ARP)";
        if("22F3".equals(hex))
            return "Wake on LAN";
        if("22F3".equals(hex))
            return "IETF TRILL Protocol";
        if("6003".equals(hex))
            return "DECnet Phase IV";
        if("8035".equals(hex))
            return "Reverse Address Resolution Protocol";
        if("809B".equals(hex))
            return "AppleTalk (Ethertalk)";
        if("80F3".equals(hex))
            return "AppleTalk Address Resolution Protocol (AARP)";
        if("8100".equals(hex))
            return "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq";
        if("8137".equals(hex))
            return "IPX";
        if("8204".equals(hex))
            return "QNX Qnet";
        if("86DD".equals(hex))
            return "Internet Protocol Version 6 (IPv6)";
        if("8808".equals(hex))
            return "Ethernet Flow Control";
        if("8819".equals(hex))
            return "CobraNet";
        if("8847".equals(hex))
            return "MPLS unicast";
        if("8848".equals(hex))
            return "MPLS multicast";
        if("8863".equals(hex))
            return "PPPoE Discovery Stage";
        if("8864".equals(hex))
            return "PPPoE Session Stage";
        if("8870".equals(hex))
            return "Jumbo Frames (proposed)";
        if("887B".equals(hex))
            return "HomePlug 1.0 MME";
        if("888E".equals(hex))
            return "EAP over LAN (IEEE 802.1x)";
        if("8892".equals(hex))
            return "PROFINET Protocol";
        if("889A".equals(hex))
            return "HyperSCSI (SCSI over Ethernet)";
        if("88A2".equals(hex))
            return "ATA over Ethernet";
        if("88A4".equals(hex))
            return "EtherCAT Protocol";
        if("88A8".equals(hex))
            return "Provider Bridging (IEEE 802.1ad) & shortest Path Bridging IEEE 802.1aq";
        if("88AB".equals(hex))
            return "Ethernet Powerlink";
        if("88CC".equals(hex))
            return "Link Layer Discovery Protocol (LLDP)";
        if("88CD".equals(hex))
            return "SERCOS III";
        if("88E1".equals(hex))
            return "HomePlug AV MME";
        if("88E3".equals(hex))
            return "Media Redundancy Protocol (IEC62439-2)";
        if("88E5".equals(hex))
            return "MAC security (IEEE 802.1AE)";
        if("88E6".equals(hex))
            return "Provider Backbone Bridges (PBB) (IEEE 802.1ah)";
        if("88F7".equals(hex))
            return "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)";
        if("8902".equals(hex))
            return "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731(OAM)";
        if("8906".equals(hex))
            return "Fribe Channel over Ethernet (FCoE)";
        if("8914".equals(hex))
            return "FCoE Initialization Protocol";
        if("8915".equals(hex))
            return "RDMA over Converged Ethernet (RoCE)";
        if("891D".equals(hex))
            return "TTRthernet Protocol Control Frame(TTE)";
        if("892F".equals(hex))
            return "High-availability Seamiess Redundancy (HSR)";
        if("9000".equals(hex))
            return "Ethernet Configuration Testing Protocol";



        return "Error - No se encontro el protocolo";
    }
    
    public String getComplementA1(String binary){
        String aux = "";
        for(int x = 0; x < binary.length(); x++){
            if(binary.charAt(x) == '0'){
                aux += '1';
            }else if(binary.charAt(x) == '1'){
                aux += '0';
            }
        }
        return aux;
    }
    
    public String sumBinary(String binary1, String binary2){
        String result = "";
        int acarreo = 0;
        int sizeBinary1 = binary1.length();
        int sizeBinary2 = binary2.length();
        
        binary1 = getReverse(binary1);
        binary2 = getReverse(binary2);
        
        //igualamos la cantidad de bits de cada valor binario
        if(sizeBinary1 > sizeBinary2){
            for(int x = sizeBinary2; x < sizeBinary1; x++){
                binary2 += "0";
            }
        }else if(sizeBinary1 < sizeBinary2){
            for(int x = sizeBinary1; x < sizeBinary2; x++){
                binary1 += "0";
            }
        }
        
        
        sizeBinary1 = binary1.length();
        sizeBinary2 = binary2.length();
        
        //Con este for realizamos la suma bit por bit y llevamos el control del acarreo  
        for(int x = 0; x < sizeBinary1; x++){
            //System.out.println("x = " + x + "  sizeBinary1 = " + sizeBinary1 + "  result = " + getReverse(result) + "  acarreo = " + acarreo);
            
            if(binary1.charAt(x) == '0' && binary2.charAt(x) == '0'){
                if(acarreo == 1){
                    result += "1";
                    acarreo = 0;
                }else{
                    result += "0";
                }
            }
            else if(binary1.charAt(x) == '0' && binary2.charAt(x) == '1'){
                if(acarreo == 1){
                    result += "0";
                    acarreo = 1;
                }else{
                    result += "1";
                }
            }
            else if(binary1.charAt(x) == '1' && binary2.charAt(x) == '0'){
                if(acarreo == 1){
                    result += "0";
                    acarreo = 1;
                }else{
                    result += "1";
                }
            }else if(binary1.charAt(x) == '1' && binary2.charAt(x) == '1'){
                if(acarreo == 1){
                    result += "1";
                    acarreo = 1;
                }else{
                    result += "0";
                    acarreo = 1;
                }
            }
        }
        
        //System.out.println("Resultado = " + getReverse(result) + "  Acarreo = " + acarreo);
        
   
        //Si nos quedo acarreo entonces realizamos la suma del resultado mas el acarreo
        if(acarreo == 1){
            String acarr = "1";

            result = getReverse(result);
            
            return sumBinary(result, acarr);
        }
        
        return getReverse(result);
        
 
    }
    
    public String getReverse(String value){
        int aux = value.length();
        String reverse = "";
        
        for(int x = aux - 1; x >= 0; x--){
            reverse += String.valueOf(value.charAt(x));
        }
        return reverse;
    }
    
    private String convertHexToDecimal(String hex){
        return convertBinarytoDecimal(convertHexToBinary(hex));
    }
    
    private String convertHexToBinary(String hex){
 
        // variable to store the converted
        // Binary Sequence
        String binary = "";
 
        // converting the accepted Hexadecimal
        // string to upper case
        hex = hex.toUpperCase();
 
        // initializing the HashMap class
        HashMap<Character, String> hashMap= new HashMap<Character, String>();
 
        // storing the key value pairs
        hashMap.put('0', "0000");
        hashMap.put('1', "0001");
        hashMap.put('2', "0010");
        hashMap.put('3', "0011");
        hashMap.put('4', "0100");
        hashMap.put('5', "0101");
        hashMap.put('6', "0110");
        hashMap.put('7', "0111");
        hashMap.put('8', "1000");
        hashMap.put('9', "1001");
        hashMap.put('A', "1010");
        hashMap.put('B', "1011");
        hashMap.put('C', "1100");
        hashMap.put('D', "1101");
        hashMap.put('E', "1110");
        hashMap.put('F', "1111");
 
        int i;
        char ch;

        for (i = 0; i < hex.length(); i++) {
            ch = hex.charAt(i);
 
            if (hashMap.containsKey(ch))
                binary += hashMap.get(ch);

            else {
                binary = "Invalid Hexadecimal String";
                return binary;
            }
        }
 
        // returning the converted Binary
        return binary;
    }
    
    private String convertBinaryToHex(String binary){
 
        String hex = "";

        HashMap<String, Character> hashMap= new HashMap<String, Character>();
 
        hashMap.put("0000", '0');
        hashMap.put("0001", '1');
        hashMap.put("0010", '2');
        hashMap.put("0011", '3');
        hashMap.put("0100", '4');
        hashMap.put("0101", '5');
        hashMap.put("0110", '6');
        hashMap.put("0111", '7');
        hashMap.put("1000", '8');
        hashMap.put("1001", '9');
        hashMap.put("1010", 'A');
        hashMap.put("1011", 'B');
        hashMap.put("1100", 'C');
        hashMap.put("1101", 'D');
        hashMap.put("1110", 'E');
        hashMap.put("1111", 'F');
 
        int i;
        String ch;
        
        
        for (i = 0; i < binary.length(); i+=4) {

            ch = String.valueOf(binary.charAt(i)) + String.valueOf(binary.charAt(i+1)) + String.valueOf(binary.charAt(i+2)) + String.valueOf(binary.charAt(i+3));
           
            if (hashMap.containsKey(ch))
                hex += hashMap.get(ch); 
            else {
                hex = "Invalid Binary String";
                return hex;
            }
        }
        
        return hex;
    }
    
    public String convertBinarytoDecimal(String binary) {
        // A este número le vamos a sumar cada valor binario
        long decimal = 0;
        int posicion = 0;
        // Recorrer la cadena...
        for (int x = binary.length() - 1; x >= 0; x--) {
            // Saber si es 1 o 0; primero asumimos que es 1 y abajo comprobamos
            short digito = 1;
            if (binary.charAt(x) == '0') {
                digito = 0;
            }

            /*
                Se multiplica el dígito por 2 elevado a la potencia
                según la posición; comenzando en 0, luego 1 y así
                sucesivamente
             */
            double multiplicador = Math.pow(2, posicion);
            decimal += digito * multiplicador;
            posicion++;
        }
        return String.valueOf(decimal);
    }
    
    public String getPartOfData(String data[], int firstPos, int lastPos){
        String aux = "";
        
        for(int x = firstPos;  x <= lastPos; x++ ){
            aux += data[x];
        }
        
        return aux;
    }
    
    
}
