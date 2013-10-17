/*
 * =====================================================================================
 *
 *       Filename:  SimpleMemoryPool.hpp
 *
 *    Description:  Code to implement a simple memory pool
 *
 *        Version:  1.0
 *        Created:  08/05/2013 12:03:51
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  George Kola (), georgekola@gmail.com
 *        Company:  
 *
 * =====================================================================================
 */

#ifndef __SIMPLE_MEMORY_POOL_HPP
#define __SIMPLE_MEMORY_POOL_HPP

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

template <typename ELEMENT, size_t MAX_ELEMENTS, size_t ELEMENT_SIZE=sizeof(ELEMENT), bool PAGE_ROUNDED=true, size_t PAGE_SIZE=4096, typename COUNT_TYPE =uint16_t>
class SimpleMemoryPool{
    char * Start;
    COUNT_TYPE Stack[MAX_ELEMENTS];
    COUNT_TYPE Top;
    size_t ElementSize;

    void Init(){
       ElementSize=ELEMENT_SIZE;
       if(PAGE_ROUNDED){
           ElementSize=(ELEMENT_SIZE+(PAGE_SIZE-1))& (~(PAGE_SIZE-1));
       }
       size_t size=ElementSize*MAX_ELEMENTS;
       Start=(char *)mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
       if(unlikely(Start==MAP_FAILED)){
           perror("mmap failed");
           exit(1);
       }
       for(COUNT_TYPE i=0;i<MAX_ELEMENTS;i++){
             Stack[Top++]=MAX_ELEMENTS-1-i;
       }
    }
    public:
    SimpleMemoryPool(){
        //static_assert((ELEMENT_SIZE & (PAGE_SIZE-1))==0, "Element Size is not a multiple of page size");
        static_assert((PAGE_SIZE & (PAGE_SIZE-1))==0, "PAGE SIZE is not multiple of 2");
        Init();
    }
    ELEMENT* Get(){
        if(likely(Top > 0)){
            return (ELEMENT *)(Start + (Stack[--Top] * ElementSize));    
        }
        return NULL;
    }
    void Release(ELEMENT * ptr){
        if(likely(Top <= MAX_ELEMENTS)){
            Stack[Top++]=((char *)ptr - Start)/ElementSize;
            if(PAGE_ROUNDED){
                  madvise(ptr,ElementSize,MADV_FREE);
            }
        }
    }
    void Test(){

    }
    char *Info(size_t &size){
        size=ElementSize*MAX_ELEMENTS;
        return Start;
    }
};

#endif
