void *
ff_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset)
{
    //return rte_malloc("", len, 4096);
    int host_prot;
    int host_flags;

#ifdef FF_USE_PAGE_ARRAY
        if( len == 4096 ){
            return ff_mem_get_page();
        }
        else
#endif
        {

    assert(ff_PROT_NONE == PROT_NONE);
    host_prot = 0;
    if ((prot & ff_PROT_READ) == ff_PROT_READ)   host_prot |= PROT_READ;
    if ((prot & ff_PROT_WRITE) == ff_PROT_WRITE) host_prot |= PROT_WRITE;

    host_flags = 0;
    if ((flags & ff_MAP_SHARED) == ff_MAP_SHARED)   host_flags |= MAP_SHARED;
    if ((flags & ff_MAP_PRIVATE) == ff_MAP_PRIVATE) host_flags |= MAP_PRIVATE;
    if ((flags & ff_MAP_ANON) == ff_MAP_ANON)       host_flags |= MAP_ANON;

    void *ret = (mmap(addr, len, host_prot, host_flags, fd, offset));

    if (ret == MAP_FAILED) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB, "fst mmap failed:%s\n", strerror(errno));
        exit(1);
    }
    return ret;
    }
}

int
ff_munmap(void *addr, uint64_t len)
{
#ifdef FF_USE_PAGE_ARRAY
        if ( len == 4096 ){
            return ff_mem_free_addr(addr);
        }
#endif
    //rte_free(addr);
    //return 0;
    return (munmap(addr, len));
}
