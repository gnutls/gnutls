/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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
/* File: CertificateExample.c                        */
/* Description: An example on how to use the ASN1    */
/*              parser with the Certificate.txt file */   
/*****************************************************/

#include <stdio.h>
#include <string.h>
#include "../lib/cert_asn1.h"
#include "../lib/cert_der.h"


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
    result=asn1_read_value(cert,name,str,&len);
    if(result==ASN_ELEMENT_NOT_FOUND) break;
    k2=1;
    do{
      strcpy(name2,name);
      strcat(name2,".?");
      _asn1_ltostr(k2,counter);
      strcat(name2,counter);
      result=asn1_read_value(cert,name2,str,&len);
      if(result==ASN_ELEMENT_NOT_FOUND) break;
      strcpy(name3,name2);
      strcat(name3,".type");
      result=asn1_read_value(cert,name3,str,&len);
      strcpy(name3,name2);
      strcat(name3,".value");
      if(result==ASN_OK){
	result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-countryName",
			  str2,&len);
	if(!strcmp(str,str2)){
	  asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName",
			   &value,"certificate2-subject-C");
	  asn1_read_value(cert,name3,str,&len);
      	  asn1_get_der(value,str,len);
	  strcpy(name3,"certificate2-subject-C");
	  asn1_read_value(value,name3,str,&len);  /* CHOICE */
	  strcat(name3,".");
	  strcat(name3,str);
	  asn1_read_value(value,name3,str,&len);
	  str[len]=0;
	  strcat(answer," C=");
	  strcat(answer,str);
	  asn1_delete_structure(value);
	}
	else{
	  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationName"
			    ,str2,&len);
	  if(!strcmp(str,str2)){
	    asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName"
			     ,&value,"certificate2-subject-O");
	    asn1_read_value(cert,name3,str,&len);	  
	    asn1_get_der(value,str,len);
	    strcpy(name3,"certificate2-subject-O");
	    asn1_read_value(value,name3,str,&len);  /* CHOICE */
	    strcat(name3,".");
	    strcat(name3,str);
	    asn1_read_value(value,name3,str,&len);
	    str[len]=0;
	    strcat(answer," O=");
	    strcat(answer,str);
	    asn1_delete_structure(value);
	  }
	  else{
	    result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationalUnitName",str2,&len);
	    if(!strcmp(str,str2)){
	      asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationalUnitName",&value,"certificate2-subject-OU");
	      asn1_read_value(cert,name3,str,&len);
	      asn1_get_der(value,str,len);
	      strcpy(name3,"certificate2-subject-OU");
	      asn1_read_value(value,name3,str,&len);  /* CHOICE */
	      strcat(name3,".");
	      strcat(name3,str);
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
create_certificate(node_asn *cert_def,unsigned char *der,int *der_len)
{
  int result,k,len;
  unsigned char str[1024],*str2;
  node_asn *cert1,*value,*param,*constr;

  result=asn1_create_structure(cert_def,"PKIX1Implicit88.Certificate",&cert1,"certificate1");
 
  /* Use the next 3 lines to visit the empty certificate */
  /* printf("-----------------\n");
     asn1_visit_tree(cert1,"certificate1");   
     printf("-----------------\n"); */

  /* version: v3(2) */  
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.version","v3",0); 

  /* serialNumber: 17 */    
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.serialNumber","17",0); 

  /* signature: dsa-with-sha1 */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa-with-sha1",str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.signature.algorithm",
		     str,1);    
  
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.signature.parameters",
		     NULL,0);


  /* issuer: Country="US" Organization="gov" OrganizationUnit="nist" */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer","rdnSequence",12);

  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence","NEW",1);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST","NEW",1);
  /* C */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-countryName",str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520countryName",
			  &value,"countryName");
  result=asn1_write_value(value,"countryName","US",2);
  result=asn1_create_der(value,"countryName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",der,*der_len);


  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence","NEW",1);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST","NEW",1);
  /* O */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationName",str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName",
			  &value,"OrgName");
  result=asn1_write_value(value,"OrgName","printableString",1);
  result=asn1_write_value(value,"OrgName.printableString","gov",3);
  result=asn1_create_der(value,"OrgName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",der,*der_len);


  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence","NEW",1);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST","NEW",1);

  /* OU */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationalUnitName",
		    str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationalUnitName",&value,"OrgUnitName");
  result=asn1_write_value(value,"OrgUnitName","printableString",1);
  result=asn1_write_value(value,"OrgUnitName.printableString","nist",4);
  result=asn1_create_der(value,"OrgUnitName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",der,*der_len);


  /* validity */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.validity.notBefore","utcTime",1);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.validity.notBefore.utcTime","970630000000Z",1);

  result=asn1_write_value(cert1,"certificate1.tbsCertificate.validity.notAfter","utcTime",1);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.validity.notAfter.utcTime","971231000000Z",1);



  /* subject: Country="US" Organization="gov" OrganizationUnit="nist" */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject","rdnSequence",1);

  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence","NEW",1);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST","NEW",1);
  /* C */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-countryName",str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520countryName",
			  &value,"countryName");
  result=asn1_write_value(value,"countryName","US",2);
  result=asn1_create_der(value,"countryName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",der,*der_len);


  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence","NEW",4);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST","NEW",4);
  /* O */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationName",str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationName",
			  &value,"OrgName");
  result=asn1_write_value(value,"OrgName","printableString",1);
  result=asn1_write_value(value,"OrgName.printableString","gov",3);
  result=asn1_create_der(value,"OrgName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",der,*der_len);


  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence","NEW",4);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST","NEW",4);
  /* OU */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-at-organizationalUnitName",
		    str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.type",str,1);
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.X520OrganizationalUnitName",&value,"OrgUnitName");
  result=asn1_write_value(value,"OrgUnitName","printableString",1);
  result=asn1_write_value(value,"OrgUnitName.printableString","nist",4);
  result=asn1_create_der(value,"OrgUnitName",der,der_len);
  asn1_delete_structure(value);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",der,*der_len);


  /* subjectPublicKeyInfo: dsa with parameters=Dss-Parms */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa",str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm",str,1); 
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.Dss-Parms",&param,"parameters");
  str2="\xd4\x38"; /* only an example */
  result=asn1_write_value(param,"parameters.p",str2,128);
  str2="\xd4\x38"; /* only an example */
  result=asn1_write_value(param,"parameters.q",str2,20);
  str2="\xd4\x38"; /* only an example */
  result=asn1_write_value(param,"parameters.g",str2,128);
  result=asn1_create_der(param,"parameters",der,der_len);
  asn1_delete_structure(param);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters",der,*der_len); 


  /* subjectPublicKey */
  str2="\x02\x81"; /* only an example */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",str2,1048);

  result=asn1_write_value(cert1,"certificate1.tbsCertificate.issuerUniqueID",NULL,0);  /* NO OPTION */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.subjectUniqueID",NULL,0); /* NO OPTION */

  /* extensions */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions","NEW",1); 
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-ce-basicConstraints",
		    str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions.?LAST.extnID",str,1); /*   basicConstraints */  
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions.?LAST.critical","TRUE",1); 
  result=asn1_create_structure(cert_def,"PKIX1Implicit88.BasicConstraints",&constr,
			  "basicConstraints1");
  result=asn1_write_value(constr,"basicConstraints1.cA","TRUE",1); 
  result=asn1_write_value(constr,"basicConstraints1.pathLenConstraint",NULL,0); 
  result=asn1_create_der(constr,"basicConstraints1",der,der_len);
  result=asn1_delete_structure(constr);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions.?LAST.extnValue",der,*der_len); 


  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions","NEW",1); 
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-ce-subjectKeyIdentifier",
		    str,&len);
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions.?LAST.extnID",str,1); /* subjectKeyIdentifier */ 
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions.?LAST.critical","FALSE",1); 
  str2="\x04\x14\xe7\x26\xc5"; /* only an example */
  result=asn1_write_value(cert1,"certificate1.tbsCertificate.extensions.?LAST.extnValue",str2,22); 


  /* signatureAlgorithm: dsa-with-sha  */
  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa-with-sha1",str,&len);
  result=asn1_write_value(cert1,"certificate1.signatureAlgorithm.algorithm",str,1); 
  result=asn1_write_value(cert1,"certificate1.signatureAlgorithm.parameters",NULL,0); /* NO OPTION */  


  /* signature */
  result=asn1_create_der(cert1,"certificate1.tbsCertificate",der,der_len);
  if(result!=ASN_OK){
    printf("\n'tbsCertificate' encoding creation: ERROR\n");
    //    return;
  }
  /* add the lines for the signature on der[0]..der[der_len-1]: result in str2 */
  result=asn1_write_value(cert1,"certificate1.signature",str2,368); /* dsa-with-sha */ 
  

  /* Use the next 3 lines to visit the certificate */
  /* printf("-----------------\n");   
     asn1_visit_tree(cert1,"certificate1");  
     printf("-----------------\n"); */


  result=asn1_create_der(cert1,"certificate1",der,der_len);
  if(result!=ASN_OK){
    printf("\n'certificate1' encoding creation: ERROR\n");
    return;
  }

  /* Print the 'Certificate1' DER encoding */ 
  printf("-----------------\nCertificate1 Encoding:\nNumber of bytes=%i\n",*der_len);
  for(k=0;k<*der_len;k++) printf("%02x ",der[k]);  
  printf("\n-----------------\n");

  /* Clear the "certificate1" structure */
  asn1_delete_structure(cert1);
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
get_certificate(node_asn *cert_def,unsigned char *der,int der_len)
{
  int result,len,start,end;
  unsigned char str[1024],str2[1024];
  node_asn *cert2;

  asn1_create_structure(cert_def,"PKIX1Implicit88.Certificate",&cert2,"certificate2");

  result=asn1_get_der(cert2,der,der_len);

  if(result!=ASN_OK){
    printf("Problems with DER encoding\n");
    return;
  }
   

  /* issuer */
  get_Name_type(cert_def,cert2,"certificate2.tbsCertificate.issuer",str);
  printf("certificate2:\nissuer =%s\n",str);
  /* subject */
  get_Name_type(cert_def,cert2,"certificate2.tbsCertificate.subject",str);
  printf("subject=%s\n",str);


  /* Verify sign */
  result=asn1_read_value(cert2,"certificate2.signatureAlgorithm.algorithm"
		    ,str,&len);

  result=asn1_read_value(cert_def,"PKIX1Implicit88.id-dsa-with-sha1",str2,&len);
  if(!strcmp(str,str2)){  /* dsa-with-sha */

    result=asn1_get_start_end_der(cert2,der,der_len,
			     "certificate2.tbsCertificate",&start,&end);

    /* add the lines to calculate the sha on der[start]..der[end] */

    result=asn1_read_value(cert2,"certificate2.signature",str,&len);

    /* compare the previous value to signature ( with issuer public key) */ 
  }

  /* Use the next 3 lines to visit the certificate */
  /*   printf("-----------------\n");   
     asn1_visit_tree(cert2,"certificate2");  
     printf("-----------------\n"); */


  /* Clear the "certificate2" structure */
  asn1_delete_structure(cert2);
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

  if(argc==2) strcpy(file_name,argv[1]);
  else file_name[0]=0;

  strcat(file_name,"pkix.asn");

  result=asn1_parser_asn1(file_name,&PKIX1Implicit88);

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
     asn1_visit_tree(PKIX1Implicit88,"PKIX1Implicit88");   
     printf("-----------------\n"); */


  create_certificate(PKIX1Implicit88,der,&der_len);

  get_certificate(PKIX1Implicit88,der,der_len);

  /* Clear the "PKIX1Implicit88" structures */
  asn1_delete_structure(PKIX1Implicit88);

  return;
}









