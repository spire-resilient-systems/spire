/*
 * The Spread Toolkit.
 *     
 * The contents of this file are subject to the Spread Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spread.org/license/
 *
 * or in the file ``license.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Spread are:
 *  Yair Amir, Michal Miskin-Amir, Jonathan Stanton, John Schultz.
 *
 *  Copyright (C) 1993-2009 Spread Concepts LLC <info@spreadconcepts.com>
 *
 *  All Rights Reserved.
 *
 * Major Contributor(s):
 * ---------------
 *    Ryan Caudy           rcaudy@gmail.com - contributions to process groups.
 *    Claudiu Danilov      claudiu@acm.org - scalable wide area support.
 *    Cristina Nita-Rotaru crisn@cs.purdue.edu - group communication security.
 *    Theo Schlossnagle    jesus@omniti.com - Perl, autoconf, old skiplist.
 *    Dan Schoenblum       dansch@cnds.jhu.edu - Java interface.
 *
 */


/* memory.c
 * memory allocater and deallocater
 *
 */
#include "arch.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spu_memory.h"
#include "spu_alarm.h"
#include "spu_objects.h"

#define NO_REF_CNT             -1
#define MAX_MEM_OBJECTS         200

#define mem_header_ptr(obj) ( &( ( free_list_elem * ) ( obj ) - 1 )->header )

/************************
 * Global Variables 
 ************************/

/* Total bytes currently allocated including overhead */
static unsigned int     Mem_Bytes_Allocated;
/* Total number of objects of all types allocated currently */
static unsigned int     Mem_Obj_Allocated;
/* Total number of objects currently used by the application */
static unsigned int     Mem_Obj_Inuse;
/* Maximum bytes allocated at any one time during execution */
static unsigned int     Mem_Max_Bytes;
/* Maximum number of objects allocated at any one time */
static unsigned int     Mem_Max_Objects;
/* Maximum number of ojects used by application at any one time */
static unsigned int     Mem_Max_Obj_Inuse;


typedef struct mem_header_d 
{
        int32u   obj_type;
        int32    ref_cnt;
        size_t   block_len;
} mem_header;

typedef union free_list_elem
{
  mem_header            header;
  union free_list_elem *next;
  
} free_list_elem;

#define MAX_OBJNAME 35
#define DEFAULT_OBJNAME "Unknown Obj"


/* NOTE: Only num_obj_inpool is updated when debugging is turned off
 * (i.e. define NDEBUG) it is NECESSARY to track buffer pool size
 */
typedef struct mem_info_d
{
        bool            exist;  /* 1 = object registered, 0 = unused object number */
        size_t          size;   /* size of object in bytes (should be from sizeof so aligned ) */
        unsigned int    threshold;
        char            obj_name[MAX_OBJNAME + 1]; /* Name of the object */
#ifndef NDEBUG
        unsigned int    bytes_allocated;
        unsigned int    max_bytes;
        unsigned int    num_obj;
        unsigned int    max_obj;
        unsigned int    num_obj_inuse;
        unsigned int    max_obj_inuse;
#endif
        unsigned int    num_obj_inpool;
        free_list_elem *list_head;
} mem_info;

static mem_info Mem[MAX_MEM_OBJECTS];

#ifndef NDEBUG
 static bool Initialized;
#endif


/* Declare functions */
char    *Objnum_to_String(int32u oid);


int Mem_valid_objtype(int32u objtype) 
{
        /* if any bits set higher then max object type return failure */
        if (objtype > MAX_MEM_OBJECTS) { return(0); }

        /* if table entry is valid return that */
        return(Mem[objtype].exist);
}        

/* Size of the memory object */
static size_t sizeobj(int32u objtype)
{
        return(Mem[objtype].size);
}



/************************
 * Query Functions
 ************************/

unsigned int Mem_total_bytes() 
{
        return(Mem_Bytes_Allocated);
}
unsigned int Mem_total_inuse()
{
        return( Mem_Obj_Inuse );
}
unsigned int Mem_total_obj()              
{
        return( Mem_Obj_Allocated );
}
unsigned int Mem_total_max_bytes() 
{
        return(Mem_Max_Bytes);
}
unsigned int Mem_total_max_inuse()
{
        return( Mem_Max_Obj_Inuse );
}
unsigned int Mem_total_max_obj()              
{
        return( Mem_Max_Objects );
}
unsigned int Mem_obj_in_pool(int32u objtype)  
{
        return( Mem[objtype].num_obj_inpool);
}

#ifndef NDEBUG
unsigned int Mem_obj_in_app(int32u objtype)    
{
        return( Mem[objtype].num_obj_inuse );
}
unsigned int Mem_max_in_app(int32u objtype)
{
        return( Mem[objtype].max_obj_inuse );
}

unsigned int Mem_obj_total(int32u objtype)    
{
        return( Mem[objtype].num_obj );
}
unsigned int Mem_max_obj(int32u objtype)
{
        return( Mem[objtype].max_obj );
}
unsigned int Mem_bytes(int32u objtype)
{
        return( Mem[objtype].bytes_allocated );
}
unsigned int Mem_max_bytes(int32u objtype)
{
        return( Mem[objtype].max_bytes );
}
#endif /* NDEBUG */

/**********************
 * Internal functions
 **********************/

void            Mem_init_object_abort( int32u obj_type, char *obj_name, int32u size, unsigned int threshold, unsigned int initial )
{
        int     ret;

        ret = Mem_init_object( obj_type, obj_name, size, threshold, initial );
        if (ret < 0 ) {
                Alarm( EXIT, "Mem_init_object_abort: Failed to initialize a/an %s object\n", obj_name);
        }
}
/* Input: valid object type, name of object, threshold/watermark value for this object, initial objects to create
 * Output: none
 * Effects: sets watermark for type,creates initial memory buffers and updates global vars
 * Should ONLY be called once per execution of the program
 */
int            Mem_init_object(int32u obj_type, char *obj_name, int32u size, unsigned int threshold, unsigned int initial)
{
        int mem_error = 0;
        assert((obj_type > 0) && (obj_type < MAX_MEM_OBJECTS));
        assert(size > 0 );

#ifndef NDEBUG
        if (!Initialized) {
                /* do any initialization needed just once here */
                Mem_Bytes_Allocated = 0;
                Mem_Obj_Allocated = 0;
                Mem_Obj_Inuse = 0;
                Mem_Max_Bytes = 0;
                Mem_Max_Objects = 0;
                Mem_Max_Obj_Inuse = 0;
                
                Initialized = TRUE;
        }

        assert(!(Mem[obj_type].exist));

        if( obj_type == BLOCK_OBJECT )
        {
                assert(threshold == 0);
                assert(initial == 0);
        }
        
        Alarm( PRINT, __FILE__ ":%d: Setting mem pool threshold to 0! Not using pool ... only meant for valgrinding!\n", __LINE__ );
	threshold = 0;
#endif	
        
        Mem[obj_type].exist = TRUE;
        Mem[obj_type].size = size;
        
#ifndef  MEM_DISABLE_CACHE
        Mem[obj_type].threshold = threshold;
#else
        Mem[obj_type].threshold = 0;
#endif
        
        if (obj_name == NULL || strlen(obj_name) > MAX_OBJNAME) {
            strncpy(Mem[obj_type].obj_name, DEFAULT_OBJNAME, MAX_OBJNAME);
        } else {
            strncpy(Mem[obj_type].obj_name, obj_name, MAX_OBJNAME);
        }
        Mem[obj_type].obj_name[MAX_OBJNAME] = '\0';

#ifndef NDEBUG
        Mem[obj_type].num_obj = 0;
        Mem[obj_type].bytes_allocated = 0;
        Mem[obj_type].num_obj_inuse = 0;
        Mem[obj_type].max_bytes = 0;
        Mem[obj_type].max_obj = 0;
        Mem[obj_type].max_obj_inuse = 0;
#endif
        Mem[obj_type].num_obj_inpool = 0;
        if (initial > 0)
        {
                /* Create 'initial' objects */
                int i;
                free_list_elem *elem;
                
                for(i = initial; i > 0; i--)
                {
                        elem = ( free_list_elem * ) calloc( 1, sizeof( free_list_elem ) + sizeobj( obj_type ) );
                        
                        if ( elem == NULL ) 
                        {
                                Alarm(MEMORY, "mem_init_object: Failure to calloc an initial object. Returning with existant buffers\n");
                                mem_error = 1;
                                break;
                        }

                        elem->next                = Mem[ obj_type ].list_head;
                        Mem[ obj_type ].list_head = elem;
                        Mem[obj_type].num_obj_inpool++;
#ifndef NDEBUG
                        Mem[obj_type].num_obj++;
                        Mem[obj_type].bytes_allocated += sizeof( free_list_elem ) + sizeobj( obj_type );
#endif
                }
#ifndef NDEBUG
                Mem[obj_type].max_bytes = Mem[obj_type].bytes_allocated;    
                Mem[obj_type].max_obj = Mem[obj_type].num_obj;

                Mem_Bytes_Allocated += Mem[obj_type].bytes_allocated;
                Mem_Obj_Allocated += Mem[obj_type].num_obj;
                if (Mem_Bytes_Allocated > Mem_Max_Bytes) 
                {
                        Mem_Max_Bytes = Mem_Bytes_Allocated;
                }
                if (Mem_Obj_Allocated > Mem_Max_Objects)
                {
                        Mem_Max_Objects = Mem_Obj_Allocated;
                } 
#endif
        }

        if (mem_error) { return(-1); }
        return(0);
}


/* Input: a valid type of object
 * Output: a pointer to memory which will hold an object
 * Effects: will only allocate an object from system if none exist in pool
 */
void *          new(int32u obj_type)
{
        free_list_elem *elem;

        assert(Mem_valid_objtype(obj_type));

        if (Mem[obj_type].list_head == NULL) 
        {
                elem = ( free_list_elem * ) calloc( 1, sizeof( free_list_elem ) + sizeobj( obj_type ) );
                        
                if ( elem == NULL ) 
                {
                        Alarm(MEMORY, "mem_alloc_object: Failure to calloc an object. Returning NULL object\n");
                        return(NULL);
                }

#ifndef NDEBUG
		assert(Mem[obj_type].num_obj + 1 > Mem[obj_type].num_obj);
                Mem[obj_type].num_obj++;

		assert(Mem[obj_type].bytes_allocated + sizeof( free_list_elem ) + sizeobj( obj_type ) > Mem[obj_type].bytes_allocated);
                Mem[obj_type].bytes_allocated += sizeof( free_list_elem ) + sizeobj( obj_type );

                if (Mem[obj_type].bytes_allocated > Mem[obj_type].max_bytes)
                {
                        Mem[obj_type].max_bytes = Mem[obj_type].bytes_allocated;
                }
                if (Mem[obj_type].num_obj > Mem[obj_type].max_obj)
                {       
                        Mem[obj_type].max_obj = Mem[obj_type].num_obj;
                }

		assert(Mem_Bytes_Allocated + sizeof( free_list_elem ) + sizeobj( obj_type ) > Mem_Bytes_Allocated);
                Mem_Bytes_Allocated += sizeof( free_list_elem ) + sizeobj( obj_type );

		assert(Mem_Obj_Allocated + 1 > Mem_Obj_Allocated);
                Mem_Obj_Allocated++;

                if (Mem_Bytes_Allocated > Mem_Max_Bytes) 
                {
                        Mem_Max_Bytes = Mem_Bytes_Allocated;
                }
                if (Mem_Obj_Allocated > Mem_Max_Objects)
                {
                        Mem_Max_Objects = Mem_Obj_Allocated;
                }
#endif
                
                Alarm(MEMORY, "new: creating pointer 0x%x to object type %d named %s\n", elem + 1, obj_type, Objnum_to_String(obj_type));
        } else
        {
                assert(Mem[obj_type].num_obj_inpool > 0 );

                elem                    = Mem[ obj_type ].list_head;
                Mem[obj_type].list_head = elem->next;
                Mem[obj_type].num_obj_inpool--;
                
                Alarm(MEMORY, "new: reusing pointer 0x%x to object type %d named %s\n", elem + 1, obj_type, Objnum_to_String(obj_type));
        }

#ifndef NDEBUG
        assert(Mem[obj_type].num_obj_inuse + 1 > Mem[obj_type].num_obj_inuse);
        Mem[obj_type].num_obj_inuse++;
        
        if (Mem[obj_type].num_obj_inuse > Mem[obj_type].max_obj_inuse)
                Mem[obj_type].max_obj_inuse = Mem[obj_type].num_obj_inuse;

        assert(Mem_Obj_Inuse + 1 > Mem_Obj_Inuse);
        Mem_Obj_Inuse++;
        
        if (Mem_Obj_Inuse > Mem_Max_Obj_Inuse)
                Mem_Max_Obj_Inuse = Mem_Obj_Inuse;
#endif

        {
                mem_header *head_ptr = &elem->header;
                
                head_ptr->obj_type  = obj_type;
                head_ptr->block_len = sizeobj(obj_type);
                head_ptr->ref_cnt   = NO_REF_CNT;
        }

        return ( void * ) ( elem + 1 );
}


/* Input: a size of memory block desired
 * Output: a pointer to memory which will hold the block
 * Effects: 
 */
void *          Mem_alloc( unsigned int length)
{
        free_list_elem *elem;
        mem_header * head_ptr;

        if (length == 0) { return(NULL); }
        if( !Mem[BLOCK_OBJECT].exist )
        { 
                Mem[BLOCK_OBJECT].exist = TRUE;
                Mem[BLOCK_OBJECT].size = 0;
                Mem[BLOCK_OBJECT].threshold = 0;
        }
        
        elem = ( free_list_elem * ) calloc( 1, sizeof( free_list_elem ) + length );
        
        if ( elem == NULL )
        {
                Alarm(MEMORY, "mem_alloc: Failure to calloc a block. Returning NULL block\n");
                return(NULL);
        }

        head_ptr            = &elem->header;
        head_ptr->obj_type  = BLOCK_OBJECT;
        head_ptr->block_len = length;
	head_ptr->ref_cnt   = NO_REF_CNT;

#ifndef NDEBUG

	assert(Mem[BLOCK_OBJECT].num_obj + 1 > Mem[BLOCK_OBJECT].num_obj);
        Mem[BLOCK_OBJECT].num_obj++;

	assert(Mem[BLOCK_OBJECT].num_obj_inuse + 1 > Mem[BLOCK_OBJECT].num_obj_inuse);
        Mem[BLOCK_OBJECT].num_obj_inuse++;

	assert(Mem[BLOCK_OBJECT].bytes_allocated + sizeof( free_list_elem ) + length > Mem[BLOCK_OBJECT].bytes_allocated);
        Mem[BLOCK_OBJECT].bytes_allocated += sizeof( free_list_elem ) + length;

        if (Mem[BLOCK_OBJECT].bytes_allocated > Mem[BLOCK_OBJECT].max_bytes)
        {
                Mem[BLOCK_OBJECT].max_bytes = Mem[BLOCK_OBJECT].bytes_allocated;
        }
        if (Mem[BLOCK_OBJECT].num_obj > Mem[BLOCK_OBJECT].max_obj)
        {       
                Mem[BLOCK_OBJECT].max_obj = Mem[BLOCK_OBJECT].num_obj;
        }
        if (Mem[BLOCK_OBJECT].num_obj_inuse > Mem[BLOCK_OBJECT].max_obj_inuse)
        {
                Mem[BLOCK_OBJECT].max_obj_inuse = Mem[BLOCK_OBJECT].num_obj_inuse;
        }
        
	assert(Mem_Bytes_Allocated + sizeof( free_list_elem ) + length > Mem_Bytes_Allocated);
        Mem_Bytes_Allocated += sizeof( free_list_elem ) + length;

	assert(Mem_Obj_Allocated + 1 > Mem_Obj_Allocated);
        Mem_Obj_Allocated++;

	assert(Mem_Obj_Inuse + 1 > Mem_Obj_Inuse);
        Mem_Obj_Inuse++;

        if (Mem_Bytes_Allocated > Mem_Max_Bytes) 
        {
                Mem_Max_Bytes = Mem_Bytes_Allocated;
        }
        if (Mem_Obj_Allocated > Mem_Max_Objects)
        {
                Mem_Max_Objects = Mem_Obj_Allocated;
        }
        if (Mem_Obj_Inuse > Mem_Max_Obj_Inuse)
        {
                Mem_Max_Obj_Inuse = Mem_Obj_Inuse;
        }

#endif        
        return ( void * ) ( elem + 1 );
}


/* Input: a valid pointer to an object or block  created by new or mem_alloc
 * Output: none
 * Effects: destroys the object and frees memory associated with it if necessary 
 */
void            dispose(void *object)
{
        int32u obj_type;
	int32  ref_cnt;
        free_list_elem *elem;
        mem_header     *head_ptr;

        if (object == NULL) { return; }

        elem     = ( free_list_elem * ) object - 1;
        head_ptr = &elem->header;
        
        obj_type = head_ptr->obj_type;
	ref_cnt  = head_ptr->ref_cnt;

#ifdef TESTING
        printf("disp:object = 0x%x\n", object);
        printf("disp:mem_headerptr = 0x%x\n", head_ptr);
        printf("disp:objtype = %u:\n", head_ptr->obj_type);
        printf("disp:blocklen = %u:\n", head_ptr->block_len);
#endif

        assert(Mem_valid_objtype(obj_type));
	assert(ref_cnt == NO_REF_CNT);

#ifndef NDEBUG
        assert(Mem[obj_type].num_obj_inuse > 0);
        assert(Mem[obj_type].num_obj > 0);
        assert(Mem[ obj_type ].bytes_allocated >= sizeof( free_list_elem ) + head_ptr->block_len ) );
	assert(Mem_Obj_Inuse > 0);
	assert(Mem_Obj_Allocated > 0);
	assert(Mem_Bytes_Allocated >= sizeof( free_list_elem ) + head_ptr->block_len );

        Alarm(MEMORY, "dispose: disposing pointer 0x%x to object type %d named %s\n", object, obj_type, Objnum_to_String(obj_type));

        Mem[obj_type].num_obj_inuse--;
        Mem_Obj_Inuse--;
        if (obj_type == BLOCK_OBJECT) 
        {
                assert(Mem[obj_type].num_obj_inpool == 0);
                assert(Mem[obj_type].threshold == 0);
        }

#endif
        if ( Mem_obj_in_pool(obj_type) >= Mem[obj_type].threshold)
        {
#ifndef NDEBUG
                Mem[obj_type].num_obj--;
		Mem[obj_type].bytes_allocated -= sizeof( free_list_elem ) + head_ptr->block_len;
                Mem_Obj_Allocated--;
		Mem_Bytes_Allocated -= sizeof( free_list_elem ) + head_ptr->block_len;
#endif
                free( elem );
        } else 
        {
                elem->next                = Mem[ obj_type ].list_head;
                Mem[ obj_type ].list_head = elem;
		assert(Mem[obj_type].num_obj_inpool + 1 > Mem[obj_type].num_obj_inpool);
                Mem[obj_type].num_obj_inpool++;
        }
}
/* Input: A valid pointer to an object/block created with new or mem_alloc
 * Output: the obj_type of this block of memory
 */
int32u  Mem_Obj_Type(const void *object)
{
        int32u  obj_type;

        assert(NULL != object);
        obj_type = mem_header_ptr(object)->obj_type;
        assert(Mem_valid_objtype(obj_type));

        return(obj_type);
}

/* Input: a valid pointer to an object/block created with memalloc_object or mem_alloc
 * Output: a pointer to an object/block which is an identical copy of the object input
 * Effects: same as memalloc_object or mem_alloc
 */
void *      Mem_copy(const void *object)
{
        void * new_object;
        int32u obj_type;

        if (object == NULL) { return(NULL); }

        obj_type = mem_header_ptr(object)->obj_type;
        assert(Mem_valid_objtype(obj_type));
        if (obj_type == BLOCK_OBJECT)
        {
                new_object = (void *) Mem_alloc(mem_header_ptr(object)->block_len);
        } else 
        {
                new_object =(void *) new(obj_type);
        }
        if (new_object == NULL) { return(NULL); }

        memcpy(new_object, object, mem_header_ptr(object)->block_len);

        mem_header_ptr(new_object)->obj_type = mem_header_ptr(object)->obj_type;
        mem_header_ptr(new_object)->block_len = mem_header_ptr(object)->block_len;
        mem_header_ptr(new_object)->ref_cnt   = NO_REF_CNT;

        return(new_object);
}

/* Input: a size of memory block desired
 * Output: a pointer to memory which will hold the block
 * Effects: 
 */
void * Mem_alloc_ref_cnt(unsigned int length)
{
    void * object;

    if ((object = Mem_alloc(length)) != NULL) {
	mem_header_ptr(object)->ref_cnt = 1;
    }

    return(object);
}

/* Input: a valid type of object
 * Output: a pointer to memory which will hold an object
 * Effects: will only allocate an object from system if none exist in pool
 * The allocated object will have reference counter initiated with 1
 */
void*          new_ref_cnt(int32 obj_type)
{
    void       *object;

    if((object = new(obj_type)) != NULL) {
	mem_header_ptr(object)->ref_cnt = 1;
    }

    return(object);
}

/* Input: a valid pointer to a reference count object
 * Output: the resulting reference count
 * Effects: Increments the reference count of an object
 */
int             inc_ref_cnt(void *object)
{
    assert(object != NULL);
    assert(mem_header_ptr(object)->ref_cnt > 0);
    return(++mem_header_ptr(object)->ref_cnt);
}


/* Input: a valid pointer to a reference count object
 * Output: the resulting reference count
 * Effects: Decrements the reference count of an object. 
 * If the resulting reference count is 0, then the object is disposed
 */
int             dec_ref_cnt(void *object) 
{
    int ret;

    if(object == NULL) { return 0; }

    assert(mem_header_ptr(object)->ref_cnt > 0);
    ret = --mem_header_ptr(object)->ref_cnt;
    
    if(ret == 0) {
	mem_header_ptr(object)->ref_cnt = NO_REF_CNT;
	dispose(object);
    }
    return(ret);
}            



/* Input: a valid pointer to a reference count object
 * Output: the reference count of the object
 * Effects: Returns the reference count of an object. 
 */
int             get_ref_cnt(void *object)
{
    if(object == NULL) { return 0; }

    assert(mem_header_ptr(object)->ref_cnt > 0);
    return(mem_header_ptr(object)->ref_cnt);
}            


char    *Objnum_to_String(int32u oid)
{
    if (Mem[oid].exist) {
        return(Mem[oid].obj_name);
    } else {
        return("NO SUCH OBJECT");
    }

}


