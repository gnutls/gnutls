/*
 *      Copyright (C) 2000,2001 Fabio Fiorina
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/*****************************************************/
/* File: CrlExample.c                                */
/* Description: An example on how to use the ASN1    */
/*              parser with the Certificate.txt file */   
/*****************************************************/

#include <stdio.h>
#include <string.h>
#include "../lib/x509_asn1.h"
#include "../lib/x509_der.h"

extern static_asn pkix_asn1_tab[];

/******************************************************/
/* Function : get_name_type                           */
/* Description: analyze a structure of type Name      */
/* Parameters:                                        */
/*   char *root: the structure identifier             */
/*   char *answer: the string with elements like:     */
/*                 "C=US O=gov"                       */ 
/******************************************************/
void
get_Name_type(node_asn *cert_def,node_asn *cert,char *root, char *answer)
{
  int k,k2,result,len;
  char name[128],str[1024],str2[1024],name2[128],counter[5],name3[128];
  node_asn *value;

  answer[0]=0;
  k=1;
  do{
    strcpy(name,root);
    strcat(name,".rdnSequence.?");
    _asn1_ltostr(k,counter);
    strcat(name,counter);
    
    len = sizeof(str)-1;
    result=asn1_read_value(cert,name,str,&len);
    if(result==ASN_ELEMENT_NOT_FOUND) break;
    k2=1;
    do{
      strcpy(name2,name);
      strcat(name2,".?");
      _asn1_ltostr(k2,counter);
      strcat(name2,counter);
      
      len = sizeof(str)-1;
      result=asn1_read_value(cert,name2,str,&len);
      if(result==ASN_ELEMENT_NOT_FOUND) break;
      strcpy(name3,name2);
      strcat(name3,".type");
      
      len = sizeof(str)-1;
      result=asn1_read_value(cert,name3,str,&len);
      strcpy(name3,name2);
      strcat(name3,".value");
      if(result==ASN_OK){
	len = sizeof(str2);
	result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-countryName",
			  str2,&len);
	if(!strcmp(str,str2)){
	  asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName",
			   &value,"certificate2-subject-C");
	  len = sizeof(str)-1;
	  asn1_read_value(cert,name3,str,&len);
      	  asn1_get_der(value,str,len);
	  strcpy(name3,"certificate2-subject-C");
	  
	  len = sizeof(str)-1;
	  asn1_read_value(value,name3,str,&len);  /* CHOICE */
	  strcat(name3,".");
	  strcat(name3,str);
	  
	  len = sizeof(str)-1;
	  asn1_read_value(value,name3,str,&len);
	  str[len]=0;
	  strcat(answer," C=");
	  strcat(answer,str);
	  asn1_delete_structure(value);
	}
	else{
	  len = sizeof(str2);
	  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationName"
			    ,str2,&len);
	  if(!strcmp(str,str2)){
	    asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName"
			     ,&value,"certificate2-subject-O");
	    
	    len = sizeof(str)-1;
	    asn1_read_value(cert,name3,str,&len);	  
	    asn1_get_der(value,str,len);
	    strcpy(name3,"certificate2-subject-O");
	    len = sizeof(str)-1;
	    asn1_read_value(value,name3,str,&len);  /* CHOICE */
	    strcat(name3,".");
	    strcat(name3,str);
	    len = sizeof(str)-1;
	    asn1_read_value(value,name3,str,&len);
	    str[len]=0;
	    strcat(answer," O=");
	    strcat(answer,str);
	    asn1_delete_structure(value);
	  }
	  else{
	    len = sizeof(str2);
	    result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationalUnitName",str2,&len);
	    if(!strcmp(str,str2)){
	      asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationalUnitName",&value,"certificate2-subject-OU");
	      len = sizeof(str)-1;
	      asn1_read_value(cert,name3,str,&len);
	      asn1_get_der(value,str,len);
	      strcpy(name3,"certificate2-subject-OU");
	      len = sizeof(str)-1;
	      asn1_read_value(value,name3,str,&len);  /* CHOICE */
	      strcat(name3,".");
	      strcat(name3,str);
	      len = sizeof(str)-1;
	      asn1_read_value(value,name3,str,&len);
	      str[len]=0;
	      strcat(answer," OU=");
	      strcat(answer,str);
	      asn1_delete_structure(value);
	    }
	  }
	}
      }
      k2++;
    }while(1);
    k++;
  }while(1);
}


/******************************************************/
/* Function : create_certificate                      */
/* Description: creates a certificate named           */
/*              "certificate1". Values are the same   */
/*              as in rfc2459 Appendix D.1            */
/* Parameters:                                        */
/*   unsigned char *der: contains the der encoding    */
/*   int *der_len: number of bytes of der string      */ 
/******************************************************/
void
create_CRL(node_asn *cert_def, unsigned char *der,int *der_len)
{
  int result,k,len;
  unsigned char str[1024],*str2;
  node_asn *crl,*value;

  result=asn1_create_structure(cert_def,"PKIX1Implicit88.CertificateList",&crl,"crl1");
 
  /* Use the next 3 lines to visit the empty certificate */ 
  /*  printf("-----------------\n");
   asn1_visit_tree(crl,"crl1");   
   printf("-----------------\n"); */
   

  /* version: v2(1) */  
  result=asn1_write_value(crl,"crl1.tbsCertList.version","v2",0); 

  /* signature: dsa-with-sha */
  len = sizeof(str)-1;
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa-with-sha1",str,&len);
  result=asn1_write_value(crl,"crl1.tbsCertList.signature.algorithm",str,1);   
  
  result=asn1_write_value(crl,"crl1.tbsCertList.signature.parameters",NULL,0);


  /* issuer: Country="US" Organization="gov" OrganizationUnit="nist" */
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer","rdnSequence",1);

  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence","NEW",1);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST","NEW",1);
  /* C */
  len = sizeof(str)-1;
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-countryName",str,&len);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520countryName",
			  &value,"countryName");
  result=asn1_write_value(value,"countryName","US",2);
  result=asn1_create_der(value,"countryName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST.?LAST.value",der,*der_len);


  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence","NEW",4);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST","NEW",4);
  /* O */
  len = sizeof(str)-1;
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationName",str,&len);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST.?LAST.type",str,8);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName",
			  &value,"OrgName");
  result=asn1_write_value(value,"OrgName","printableString",1);
  result=asn1_write_value(value,"OrgName.printableString","gov",3);
  result=asn1_create_der(value,"OrgName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST.?LAST.value",der,*der_len);


  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence","NEW",1);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST","NEW",1);
  /* OU */
  len = sizeof(str)-1;
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationalUnitName",
		    str,&len);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationalUnitName",&value,"OrgUnitName");
  result=asn1_write_value(value,"OrgUnitName","printableString",1);
  result=asn1_write_value(value,"OrgUnitName.printableString","nist",4);
  result=asn1_create_der(value,"OrgUnitName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(crl,"crl1.tbsCertList.issuer.rdnSequence.?LAST.?LAST.value",der,*der_len);


  /* validity */
  result=asn1_write_value(crl,"crl1.tbsCertList.thisUpdate","utcTime",1);
  result=asn1_write_value(crl,"crl1.tbsCertList.thisUpdate.utcTime","970801000000Z",1);

  result=asn1_write_value(crl,"crl1.tbsCertList.nextUpdate","utcTime",1);
  result=asn1_write_value(crl,"crl1.tbsCertList.nextUpdate.utcTime","970808000000Z",1);


  /* revokedCertificates */
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates","NEW",1);
  str[0]=18;
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.userCertificate",str,1);
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.revocationDate","utcTime",1);
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.revocationDate.utcTime","970731000000Z",1);

  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.crlEntryExtensions","NEW",1);
  len = sizeof(str)-1;
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-ce-cRLReasons",
		    str,&len);
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.crlEntryExtensions.?LAST.extnID",str,1); /* reasonCode */
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.crlEntryExtensions.?LAST.critical","FALSE",1); 
  str2="\x0a\x01\x01";
  result=asn1_write_value(crl,"crl1.tbsCertList.revokedCertificates.?LAST.crlEntryExtensions.?LAST.extnValue",str2,3); 


  /* crlExtensions */
  result=asn1_write_value(crl,"crl1.tbsCertList.crlExtensions",NULL,0);


  /* signatureAlgorithm: dsa-with-sha  */
  len = sizeof(str)-1;
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa-with-sha1",str,&len);
  result=asn1_write_value(crl,"crl1.signatureAlgorithm.algorithm",str,1);  
  result=asn1_write_value(crl,"crl1.signatureAlgorithm.parameters",NULL,0); /* NO OPTION */  

  /* signature */
  result=asn1_create_der(crl,"crl1.tbsCertList",der,der_len);
  if(result!=ASN_OK){
    printf("\n'tbsCertList' encoding creation: ERROR\n");
    return;
  }

  /* add the lines for the signature on der[0]..der[der_len-1]: result in str2 */
  result=asn1_write_value(crl,"crl1.signature",str2,46*8);  
  

  /* Use the next 3 lines to visit the certificate */
  /* printf("-----------------\n");   
     asn1_visit_tree(crl,"crl1");  
     printf("-----------------\n"); */


  result=asn1_create_der(crl,"crl1",der,der_len);
  if(result!=ASN_OK){
    printf("\n'crl1' encoding creation: ERROR\n");
    return;
  }

  /* Print the 'Certificate1' DER encoding */ 
  printf("-----------------\nCrl1 Encoding:\nNumber of bytes=%i\n",*der_len);
  for(k=0;k<*der_len;k++) printf("%02x ",der[k]);  
  printf("\n-----------------\n");

  /* Clear the "certificate1" structure */
  asn1_delete_structure(crl);
}



/******************************************************/
/* Function : get_certificate                         */
/* Description: creates a certificate named           */
/*              "certificate2" from a der encoding    */
/*              string                                */
/* Parameters:                                        */
/*   unsigned char *der: the encoding string          */
/*   int der_len: number of bytes of der string      */ 
/******************************************************/
void
get_CRL(node_asn *cert_def,unsigned char *der,int der_len)
{
  int result,len,start,end;
  unsigned char str[1024],str2[1024];
  node_asn *crl2;


  asn1_create_structure(cert_def,"PKIX1Implicit88.CertificateList",&crl2,"crl2");

  result=asn1_get_der(crl2,der,der_len);
  
  if(result!=ASN_OK){
    printf("Problems with DER encoding\n");
    return;
  }
   

  /* issuer */
  get_Name_type(cert_def,crl2,"crl2.tbsCertList.issuer",str);
  printf("crl2:\nissuer =%s\n",str);


  /* Verify sign */
  len = sizeof(str)-1;
  result=asn1_read_value(crl2,"crl2.signatureAlgorithm.algorithm",str,&len);

  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa-with-sha1",str2,&len);
  if(!strcmp(str,str2)){  /* dsa-with-sha */

    result=asn1_get_start_end_der(crl2,der,der_len,
			     "crl2.tbsCertList",&start,&end);

    /* add the lines to calculate the sha on der[start]..der[end] */

    result=asn1_read_value(crl2,"crl2.signature",str,&len);

    /* compare the previous value to signature ( with issuer public key) */ 
  }

  /* Use the next 3 lines to visit the certificate */
  /* printf("-----------------\n");   
     asn1_visit_tree(crl2,"crl2");  
     printf("-----------------\n"); */


  /* Clear the "crl2" structure */
  asn1_delete_structure(crl2);
}


/********************************************************/
/* Function : main                                      */
/* Description: reads the certificate description.      */
/*              Creates a certificate and calculate     */
/*              the der encoding. After that creates    */  
/*              another certificate from der string     */
/********************************************************/
int
main(int argc,char *argv[])
{
  int result,der_len;
  unsigned char der[1024];
  char file_name[128];
  node_asn *PKIX1Implicit88;

  result=asn1_create_tree(pkix_asn1_tab,&PKIX1Implicit88);

  if(result==ASN_FILE_NOT_FOUND){
    printf("FILE NOT FOUND\n");
    return;
  }
  else if(result==ASN_SYNTAX_ERROR){
    printf("PARSE ERROR\n");
    return;
  }
  else if(result==ASN_IDENTIFIER_NOT_FOUND){
    printf("IDENTIFIER NOT FOUND\n");
    return;
  }

  
  /* Use the following 3 lines to visit the PKIX1Implicit structures */
  /* printf("-----------------\n");
     asn1_visit_tree(cert_def,"PKIX1Implicit88");   
     printf("-----------------\n"); */

    
  create_CRL(PKIX1Implicit88,der,&der_len);

  get_CRL(PKIX1Implicit88,der,der_len);

  /* Clear the "PKIX1Implicit88" structures */
  asn1_delete_structure(PKIX1Implicit88);

  return;
}









