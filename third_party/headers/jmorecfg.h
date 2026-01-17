#ifndef JMORECFG_H
#define JMORECFG_H

typedef unsigned char boolean;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef unsigned char JSAMPLE;
#define MAXJSAMPLE 255
#define CENTERJSAMPLE 128

typedef unsigned char JOCTET;

typedef unsigned short J12SAMPLE;
typedef unsigned short J16SAMPLE;

typedef short JCOEF;

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef short INT16;
typedef unsigned int UINT32;
typedef int INT32;

typedef unsigned int JDIMENSION;

#ifndef EXTERN
#define EXTERN(type) extern type
#endif

#endif /* JMORECFG_H */
