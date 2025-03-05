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

#include "queue.h"


sentinal * sent;

void queue_init() {
    sent = malloc(sizeof(sentinal));
    sent->first = NULL;
    sent->last = NULL;
}

void enqueue(int val){
    node * new = malloc(sizeof(node));
    new->next = NULL;
    new->val = val;
    if(sent->first == NULL)
        sent->last = new;
    else
        sent->first->next = new;
    sent->first = new; 
}

int dequeue(){
    node * leave = sent->last;
    if(leave == NULL) {
        fputs("QUEUE EMPTY", stderr);
        exit(0);
    }
    int ret = leave->val;
    sent->last = leave->next;
    if(sent->last == NULL)
        sent->first = NULL;
    free(leave);
    return ret;
}

int queue_is_empty(){
    return sent->first == NULL;
}

void queue_del() {
    while(!queue_is_empty())
        dequeue();
    free(sent);
    sent = NULL;
}
