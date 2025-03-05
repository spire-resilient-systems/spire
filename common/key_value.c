/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt 
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu 
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS 
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "key_value.h"

/*functions */
void key_value_init(); 
int  key_value_insert( int key, int data );
int  key_value_delete( int key );
int  key_value_get   ( int key, int *data );
void key_value_print ( int print_elements );

/*element structure */
typedef struct element{
	int key;
	int data;
	struct element *next;
}element;

unsigned int count;/*num steps */
int size;/*size of list */
element start;

/*Initialize the data structure */
void key_value_init(){
	start.key = -1;
	start.data = -1;
	start.next = NULL;
	size = 0;
	count = 0;
}

/*Returns 1 if element is inserted, 0 if not, -1 if error */
int  key_value_insert( int key, int data ){
	element *pelement, *velement;
	pelement = &start;
	/*loop through looking for element. Stops when at spot to be inserted */
	while(pelement->next != NULL && pelement->next->key <=key){
		if(pelement->next->key == key) return 0;
		pelement = pelement->next;
		count ++;
	}
	
	/*insert element */
	velement = malloc(sizeof(element));
	if(velement == NULL) return -1;
	velement->key = key;
	velement->data = data;
	velement->next = pelement->next;
	count++;
	pelement->next = velement;
	count ++;
	size++;
	return 1;
}
/*return 1 if element is deleted, 0 if not, -1 if error */
int  key_value_delete( int key ){
	element *pelement, *telement;
	pelement = &start;
	/*loop thru looking for element. If there, deletes, if not exit */
	while(pelement->next != NULL && pelement->next->key <= key){
		if(pelement->next->key == key){
			telement = pelement->next;
			pelement->next = telement->next;
			free(telement);
			count += 2;
			size--;
			return 1;
		}
		pelement = pelement->next;
		count ++;
	}
	return 0;
}

/* Return 1 if element is in list, 0 if not */
int  key_value_get   ( int key, int *data ){
	element *pelement;
	pelement = &start;
	/*loop thru looking for element. IF found make *data point to data found */
	while(pelement != NULL && pelement->key <= key){
		if(pelement->key == key){
			*data = pelement->data;
			return 1;
		}
		pelement = pelement->next;
		count ++;
	}
	return 0;
}
