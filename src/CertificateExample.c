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
get_Name_type(char *root, char *answer)
{
  int k,k2,result,len;
  char name[128],str[1024],name2[128],counter[5],name3[128];

  answer[0]=0;
  k=1;
  do{
    strcpy(name,root);
    strcat(name,".rdnSequence.?");
    ltostr(k,counter);
    strcat(name,counter);
    result=read_value(name,str,&len);
    if(result==ASN_ELEMENT_NOT_FOUND) break;
    k2=1;
    do{
      strcpy(name2,name);
      strcat(name2,".?");
      ltostr(k2,counter);
      strcat(name2,counter);
      result=read_value(name2,str,&len);
      if(result==ASN_ELEMENT_NOT_FOUND) break;
      strcpy(name3,name2);
      strcat(name3,".type");
      result=read_value(name3,str,&len);
      strcpy(name3,name2);
      strcat(name3,".value");
      if(result==ASN_OK){
	if(!strcmp(str,"2 5 4 6")){
	  create_structure("certificate2-subject-C","PKIX1Explicit88.X520OrganizationName");  //X520countryName");
	  read_value(name3,str,&len);
      	  get_der("certificate2-subject-C",str,len);
	  strcpy(name3,"certificate2-subject-C");
	  read_value(name3,str,&len);  /* CHOICE */
	  strcat(name3,".");
	  strcat(name3,str);
	  read_value(name3,str,&len);
	  str[len]=0;
	  strcat(answer," C=");
	  strcat(answer,str);
	  delete_structure("certificate2-subject-C");
	}
	else if(!strcmp(str,"2 5 4 10")){
	  create_structure("certificate2-subject-O","PKIX1Explicit88.X520OrganizationName");
	  read_value(name3,str,&len);	  
	  get_der("certificate2-subject-O",str,len);
	  strcpy(name3,"certificate2-subject-O");
	  read_value(name3,str,&len);  /* CHOICE */
	  strcat(name3,".");
	  strcat(name3,str);
	  read_value(name3,str,&len);
	  str[len]=0;
	  strcat(answer," O=");
	  strcat(answer,str);
	  delete_structure("certificate2-subject-O");
	}
	else if(!strcmp(str,"2 5 4 11")){
	  create_structure("certificate2-subject-OU","PKIX1Explicit88.X520OrganizationalUnitName");
	  read_value(name3,str,&len);
	  get_der("certificate2-subject-OU",str,len);
	  strcpy(name3,"certificate2-subject-OU");
	  read_value(name3,str,&len);  /* CHOICE */
	  strcat(name3,".");
	  strcat(name3,str);
	  read_value(name3,str,&len);
	  str[len]=0;
	  strcat(answer," OU=");
	  strcat(answer,str);
	  delete_structure("certificate2-subject-OU");
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
create_certificate(unsigned char *der,int *der_len)
{
  int result,k,len;
  unsigned char str[1024],*str2;


  result=create_structure("certificate1","PKIX1Explicit88.Certificate");
 
  /* Use the next 3 lines to visit the empty certificate */
  /* printf("-----------------\n");
     visit_tree("certificate1");   
     printf("-----------------\n"); */

  /* version: 2 */
  str[0]=0x02;    
  result=write_value("certificate1.tbsCertificate.version",str,1); 

  /* serialNumber: 17 */
  str[0]=17;    
  result=write_value("certificate1.tbsCertificate.serialNumber",str,1); 

  /* signature: dsa-with-sha */
  result=write_value("certificate1.tbsCertificate.signature.algorithm","1 2 840 10040 4 3",17);   
  
  result=write_value("certificate1.tbsCertificate.signature.parameters",NULL,0);

  /* issuer: Country="US" Organization="gov" OrganizationUnit="nist" */
  result=write_value("certificate1.tbsCertificate.issuer","rdnSequence",12);

  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence","NEW",4);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST","NEW",4);
  /* C */
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type","2 5 4 6",8);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",
		     "PKIX1Explicit88.X520countryName",13);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value","US",2);


  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence","NEW",4);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST","NEW",4);
  /* O */
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type","2 5 4 10",8);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",
		     "PKIX1Explicit88.X520OrganizationName",13);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",
  		     "printableString",1);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value.printableString",
  	     "gov",3);

  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence","NEW",4);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST","NEW",4);
  /* OU */
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type","2 5 4 11",8);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",
		     "PKIX1Explicit88.X520OrganizationalUnitName",13);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value",
  		     "printableString",1);
  result=write_value("certificate1.tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value.printableString",
		     "nist",4);

  /* validity */
  result=write_value("certificate1.tbsCertificate.validity.notBefore","utcTime",1);
  result=write_value("certificate1.tbsCertificate.validity.notBefore.utcTime","970630000000Z",1);

  result=write_value("certificate1.tbsCertificate.validity.notAfter","utcTime",1);
  result=write_value("certificate1.tbsCertificate.validity.notAfter.utcTime","971231000000Z",1);



  /* subject: Country="US" Organization="gov" OrganizationUnit="nist" */
  result=write_value("certificate1.tbsCertificate.subject","rdnSequence",1);

  result=write_value("certificate1.tbsCertificate.subject.rdnSequence","NEW",1);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST","NEW",1);
  /* C */
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.type","2 5 4 6",1);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",
		     "PKIX1Explicit88.X520countryName",13);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value","US",2);

  result=write_value("certificate1.tbsCertificate.subject.rdnSequence","NEW",4);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST","NEW",4);
  /* O */
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.type","2 5 4 10",8);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",
		     "PKIX1Explicit88.X520OrganizationName",13);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",
  		     "printableString",1);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value.printableString",
  	     "gov",3);

  result=write_value("certificate1.tbsCertificate.subject.rdnSequence","NEW",4);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST","NEW",4);
  /* OU */
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.type","2 5 4 11",8);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",
		     "PKIX1Explicit88.X520OrganizationalUnitName",13);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value",
  		     "printableString",1);
  result=write_value("certificate1.tbsCertificate.subject.rdnSequence.?LAST.?LAST.value.printableString",
		     "nist",4);


  /* subjectPublicKeyInfo: dsa with parameters=Dss-Parms */
  result=write_value("certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm","1 2 840 10040 4 1",1); 
  result=write_value("certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters","Dss-Parms",1); 
  str2="\xd4\x38"; /* only an example */
  result=write_value("certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters.p",str2,128);
  str2="\xd4\x38"; /* only an example */
  result=write_value("certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters.q",str2,20);
  str2="\xd4\x38"; /* only an example */
  result=write_value("certificate1.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters.g",str2,128);

  /* subjectPublicKey */
  str2="\x02\x81"; /* only an example */
  result=write_value("certificate1.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey",str2,1048);

  result=write_value("certificate1.tbsCertificate.issuerUniqueID",NULL,0);  /* NO OPTION */
  result=write_value("certificate1.tbsCertificate.subjectUniqueID",NULL,0); /* NO OPTION */

  /* extensions */
  result=write_value("certificate1.tbsCertificate.extensions","NEW",1); 
  result=write_value("certificate1.tbsCertificate.extensions.?LAST.extnID","2 5 29 19",1); /*   basicConstraints */  
  result=write_value("certificate1.tbsCertificate.extensions.?LAST.critical","TRUE",1); 
  str2="\x30\x03\x01\x01\xff"; /* only an example */
  result=write_value("certificate1.tbsCertificate.extensions.?LAST.extnValue",str2,5); 

  result=write_value("certificate1.tbsCertificate.extensions","NEW",1); 
  result=write_value("certificate1.tbsCertificate.extensions.?LAST.extnID","2 5 29 14",1); /* subjectKeyIdentifier */ 
  result=write_value("certificate1.tbsCertificate.extensions.?LAST.critical","FALSE",1); 
  str2="\x04\x14\xe7\x26\xc5"; /* only an example */
  result=write_value("certificate1.tbsCertificate.extensions.?LAST.extnValue",str2,22); 

  /* signatureAlgorithm: dsa-with-sha  */
  result=write_value("certificate1.signatureAlgorithm.algorithm","1 2 840 10040 4 3",1);  
  result=write_value("certificate1.signatureAlgorithm.parameters",NULL,0); /* NO OPTION */  

  /* signature */
  result=create_der("certificate1.tbsCertificate",der,der_len);
  if(result!=ASN_OK){
    printf("\n'tbsCertificate' encoding creation: ERROR\n");
    return;
  }
  /* add the lines for the signature on der[0]..der[der_len-1]: result in str2 */
  result=write_value("certificate1.signature",str2,368); /* dsa-with-sha */ 
  

  /* Use the next 3 lines to visit the certificate */
  /* printf("-----------------\n");   
     visit_tree("certificate1");  
     printf("-----------------\n"); */


  result=create_der("certificate1",der,der_len);
  if(result!=ASN_OK){
    printf("\n'certificate1' encoding creation: ERROR\n");
    return;
  }

  /* Print the 'Certificate1' DER encoding */ 
  printf("-----------------\nCertificate1 Encoding:\nNumber of bytes=%i\n",*der_len);
  for(k=0;k<*der_len;k++) printf("%02x ",der[k]);  
  printf("\n-----------------\n");

  /* Clear the "certificate1" structure */
  delete_structure("certificate1");
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
get_certificate(unsigned char *der,int der_len)
{
  int result,len,start,end;
  unsigned char str[1024];


  create_structure("certificate2","PKIX1Explicit88.Certificate");

  result=get_der("certificate2",der,der_len);
  
  if(result!=ASN_OK){
    printf("Problems with DER encoding\n");
    return;
  }
   

  /* issuer */
  get_Name_type("certificate2.tbsCertificate.issuer",str);
  printf("certificate2:\nissuer =%s\n",str);
  /* subject */
  get_Name_type("certificate2.tbsCertificate.subject",str);
  printf("subject=%s\n",str);


  /* Verify sign */
  result=read_value("certificate2.signatureAlgorithm.algorithm",str,&len);

  if(!strcmp(str,"1 2 840 10040 4 3")){  /* dsa-with-sha */

    result=get_start_end_der("certificate2",der,der_len,
			     "certificate2.tbsCertificate",&start,&end);

    /* add the lines to calculate the sha on der[start]..der[end] */

    result=read_value("certificate2.signature",str,&len);

    /* compare the previous value to signature ( with issuer public key) */ 
  }

  /* Use the next 3 lines to visit the certificate */
  /* printf("-----------------\n");   
     visit_tree("certificate2");  
     printf("-----------------\n"); */


  /* Clear the "certificate2" structure */
  delete_structure("certificate2");
}


/********************************************************/
/* Function : main                                      */
/* Description: reads the certificate description.      */
/*              Creates a certificate and calculate     */
/*              the der encoding. After that creates    */  
/*              another certificate from der string     */
/********************************************************/
int
main(void)
{
  int result,der_len;
  unsigned char der[1024];

  result=parser_asn1("Certificate.txt");

  if(result==ASN_SYNTAX_ERROR){
    printf("PARSE ERROR\n");
    return;
  }
  else if(result==ASN_IDENTIFIER_NOT_FOUND){
    printf("IDENTIFIER NOT FOUND\n");
    return;
  }

  
  /* Use the following 3 lines to visit the PKIX1Explicit structures */
  /* printf("-----------------\n");
     visit_tree("PKIX1Explicit88");   
     printf("-----------------\n"); */

  create_certificate(der,&der_len);


  get_certificate(der,der_len);

  /* Clear the "PKIX1Explicit88" structures */
  delete_structure("PKIX1Explicit88");

  return;
}









