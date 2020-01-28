/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/

#include <common.h>
#include <linux/types.h>
#include "sli/sli_list.h"

static int freefunc(entry_t* item,void* data)
{
	if (data)
	{
		ITERFUNC freefunc=(ITERFUNC)data;
		freefunc(item,0);
	}
	FREE(item);
	return 0;
}


static int countfunc(entry_t* e,void* data)
{
	*(int*)data+=1;
	return 0;
}

//-----------------------------------------------


list_t* newList()
{
	list_t* res=(list_t*)MALLOC(sizeof(list_t));
	res->head=0;
	res->tail=0;
	return res;
}

void appendEntry(list_t* list,void* data)
{
	entry_t* entry=(entry_t*)MALLOC(sizeof(entry_t));
	if (entry)
	{
		entry->data=data;
		entry->next=0;
		entry->prev=0;
		if (list->head==0 || list->tail==0)
		{
			list->head=entry;
			list->tail=entry;
		}
		else
		{
			list->tail->next=entry;
			entry->prev=list->tail;
			list->tail=entry;
		}
	}
	else
		puts("OUT OF MEMORY!!!\n");
}

void deleteEntry(list_t* list,entry_t* entry)
{
	if(!entry)
		return;

	if (entry->prev)
		entry->prev->next=entry->next;

	if (entry->next)
		entry->next->prev=entry->prev;

	if(!list)
		return;

	if(entry == list->head)
		list->head = entry->next;
	if(entry == list->tail)
		list->tail = entry->prev;
}

void freeList(list_t* list,ITERFUNC freeback)
{
	iterateList(list,0,freefunc,freeback);
	FREE(list);
}


int iterateList(list_t* list,entry_t* start,ITERFUNC callback,void* data)
{
	entry_t* ptr=start;
	int cbackres=0;

	if (ptr==0)
		ptr=list->head;
	
	while (ptr)
	{
		entry_t* next=ptr->next;
		cbackres=callback(ptr,data);
		if (cbackres)
			break;
		ptr=next;
	}
	return cbackres;
}

entry_t* searchList(list_t* list,entry_t* start,ITERFUNC compback,void* data)
{
	entry_t* ptr=start;
	entry_t* res=0;
	int cbackres=0;

	if (ptr==0)
		ptr=list->head;
	
	while (ptr)
	{
		entry_t* next=ptr->next;
		cbackres=compback(ptr,data);
		if (cbackres)
		{
			res=ptr;
			break;
		}
		ptr=next;
	}
	return res;
}

int getListCount(list_t* list)
{
	int res=0;
	iterateList(list,0,countfunc,&res);
	return res;
}
