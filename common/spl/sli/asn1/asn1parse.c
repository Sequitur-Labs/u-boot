#include <common.h>
#include <sli/asn1/asn1.h>


//-----------------------------------------------
// private
static dernode* newNode( void )
{
	dernode* res=(dernode*)ASN1_MALLOC(sizeof(dernode));
	if(!res){
		debug("Failed to allocate new node\n");
		return NULL;
	}
	memset(res, 0, sizeof(dernode));
	return res;
}

static int fillContentLength(size_t* length,size_t* lengthsize,uint8_t* buffer,size_t bufferindex)
{
	int res=AP_OK;

	*length=0;
	*lengthsize=0;

	if (buffer[bufferindex]<128)
	{
		*length=(size_t)buffer[bufferindex];
		*lengthsize=1;
	}
	else
	{
		if (buffer[bufferindex]>0x80)
		{
			// get length byte length
			unsigned int numbytes=buffer[bufferindex]-128;
			size_t clen=0;
			uint8_t* clenptr=(uint8_t*)(&clen);
			int bufferptr;

			if (numbytes<=sizeof(size_t))
			{
				// convert to LITTLE_ENDIAN
				for (bufferptr=numbytes;bufferptr>0;bufferptr--)
				{
					*clenptr=buffer[bufferindex+bufferptr];
					clenptr++;
				}

				*length=clen;
				*lengthsize=numbytes+1;
			}
			else
				res=AP_ERROR_LENGTH_OVERFLOW;
		}
		else
			res=AP_ERROR_LENGTH_UNKNOWN;
	}
	
	return res;
}

static int fillNode(dernode* node,size_t* nodesize,uint8_t* buffer,size_t bufferindex)
{
	int res=AP_OK;
	size_t lengthsize;
	*nodesize=0;


	node->cls=(buffer[bufferindex]&0xC0)>>6;
	node->composition=(buffer[bufferindex]&0x20)>>5;
	node->tag=buffer[bufferindex]&0x1F;

	*nodesize+=1;

	res=fillContentLength(&node->length,&lengthsize,buffer,bufferindex+*nodesize);
	if (res==AP_OK)
	{
		*nodesize+=lengthsize;
		node->content=&(buffer[bufferindex+*nodesize]);
		*nodesize+=node->length;
	}

	node->raw=&buffer[bufferindex];
	node->rawlength=*nodesize;


	return res;
}

//-----------------------------------------------
// public
int asn1_parseDER(dernode** destnode,uint8_t* buffer,size_t buffersize)
{
	int res=AP_OK;
	size_t nodesize;
	size_t bufferptr=0;

	//debug("buffersize = %d\n",buffersize);
	//clrHeapReport(0, 0);
	dernode* node=newNode();
	dernode* parent=node;

	if(!parent) return -1;

	while (bufferptr<buffersize && node)
	{

		res=fillNode(node,&nodesize,buffer,bufferptr);
		if (res)
			break;

		bufferptr+=nodesize;
		//debug("bufferptr = %d nodesize = %d buffersize = %d\n",bufferptr,nodesize,buffersize);
		if (node->composition)
			asn1_parseDER(&node->children,node->content,node->length);

		if (bufferptr<buffersize)
		{
			node->next=newNode();
			node=node->next;
		}
	}

	if (res)
	{
		asn1_freeTree(parent,AP_FREENODEONLY);
		parent=0;
	}

	*destnode=parent;
	return res;
}

dernode * asn1_parseSingleNode( uint8_t *buffer, size_t buffersize ){
	size_t nodesize=0;
	size_t bufferptr=0;
	dernode* node=newNode();

	fillNode(node,&nodesize,buffer,bufferptr);

	return node;
}

int asn1_getSiblingCount(dernode* node)
{
	int res=0;
	if (node)
	{
		dernode* ptr=node->next;
		res=1;
		while (ptr)
		{
			ptr=ptr->next;
			res++;
		}
	}
	return res;
}

dernode* asn1_getSibling(dernode* node,int index)
{
	dernode* res=0;
	if (node)
	{
		dernode* ptr=node;
		int derindex=0;

		while (ptr)
		{
			if (derindex==index)
			{
				res=ptr;
				break;
			}
			ptr=ptr->next;
			derindex++;
		}
	}
	return res;
}

int asn1_getChildCount(dernode* node)
{
	return asn1_getSiblingCount(node->children);
}

dernode* asn1_getChild(dernode* node,int index)
{
	return asn1_getSibling(node->children,index);
}
//-----------------------------------------------
//-----------------------------------------------
//-----------------------------------------------
/* SEQLABS_VTING <-- */ 
