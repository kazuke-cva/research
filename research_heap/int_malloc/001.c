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

  if (!checked_request2size (bytes, &nb)) // chuẩn hóa kích thước yêu cầu malloc (nhỏ nhất), đồng thời nếu kích thước ko phù hợp (lớn quá hoặc bằng 0) thì trả về null
    {
      __set_errno (ENOMEM);
      return NULL; // Nếu hàm checked_request2size() trả về False thì trả về NULL luôn
    }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  /* Không có khu vực nào sử dụng được. Trở lại tới sysmalloc để lấy chunk từ mmap */
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
  /* Nếu kích thước đủ điều kiện là 1 fastbin, đầu tiên kiểm tra bin tương ứng
    Nếu bin này chưa được thực thi thậm chí chưa được khởi tạo, vì vậy chúng ta 
    cần thử kiểm tra có nó không, điều này tiết kiệm thời gian trên con đường nhanh này */

#define REMOVE_FB(fb, victim, pp)			\  // Khai báo 1 macro lấy chunk trong bin
  do							\
    {							\
      victim = pp;					\  // victim sẽ là chunk được lấy ra = pp là chunk đầu tiên trong bin
      if (victim == NULL)				\  // Nếu không có chunk nào trong bin thì thoát vòng lặp
      	break;						\
      pp = REVEAL_PTR (victim->fd);                                     \  // pp sẽ là chunk tiếp theo trong bin, ta đi sâu xem cách lấy chunk với con trỏ bị mã hóa
      if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \  // Kiểm tra xem pp khác NULL đồng thời có chia hết cho 16 không
      	malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \  // Nếu không thì heap bị hỏng và báo lỗi
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \ // Tcache bin sử dụng trong nhiều thread nên cái này đảm bảo không có thread nào lấy trùng chunk, lấy thành công chunk thì thoát vòng lắp
	        != victim);					\

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ())) // Nếu kích thước cấp phát nhỏ hơn hoặc bằng kích thước lớn nhất fastbin
    {
      idx = fastbin_index (nb); // lấy idx phù hợp với kích thước cấp phát
      mfastbinptr *fb = &fastbin (av, idx); // fb --> về chunk tương ứng với idx
      mchunkptr pp; // khai báo biến kiểu malloc_chunk
      victim = *fb; // victim là chunk được lấy ra bằng với fb đang trỏ

      if (victim != NULL) // nếu có chunk thì dùng chunk đấy
      	{
      	  if (__glibc_unlikely (misaligned_chunk (victim))) // Kiểm tra địa chỉ chunk có hợp lệ không (chia hết 0xf)
      	    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

      	  if (SINGLE_THREAD_P) // Nếu chương trình đơn luồng
      	    *fb = REVEAL_PTR (victim->fd); // giải mã con trỏ victim->fd và fb sẽ trỏ tới con trỏ ở chunk kế tiếp
      	  else
      	    REMOVE_FB (fb, pp, victim); // Không phải đơn luồng thì gọi macro REMOVE_FB để xử lý (phức tạp hơn)
      	  if (__glibc_likely (victim != NULL)) // Kiểm tra chunk vừa lấy ra
      	    {
      	      size_t victim_idx = fastbin_index (chunksize (victim)); // Tính lại idx chunk vừa lấy
      	      if (__builtin_expect (victim_idx != idx, 0))  // Khác idx vừa lấy thì crash
      		      malloc_printerr ("malloc(): memory corruption (fast)");
      	      check_remalloced_chunk (av, victim, nb); // Cái này check chunk có thuộc vùng heap quản lý không, với size của chunk có hợp lệ không(Thường thì phải bật MALLOC_CHECK_ thì mới kiểm tra bước này)
#if USE_TCACHE // Nếu bật USE_TCACHE
	             /* While we're here, if we see other chunks of the same size,
		              stash them in the tcache.  */
              /* Khi chúng ta ở đây, nếu chúng ta thấy 1 chunks khác có cùng size, chuyển chúng vào tcache */
      	      size_t tc_idx = csize2tidx (nb);
      	      if (tcache && tc_idx < mp_.tcache_bins)
            		{
            		  mchunkptr tc_victim;

            		  /* While bin not empty and tcache not full, copy chunks.  */
                  /* Trong khi bin không trống và tcache không đầy, copy chunks */
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
      	      void *p = chunk2mem (victim); // p = chunk lấy ra
      	      alloc_perturb (p, bytes);  // convert lại dữ liệu chunk --> tránh leak địa chỉ
      	      return p; // Trả về địa chỉ chunk
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
  /* Nếu là yêu cầu nhỏ, kiểm tra smallbins bin. Vì mỗi smallbins chỉ có 1 kích thước
  ,nên không cần tìm kiếm trong bin. (Đối với yêu cầu lớn, chúng ta cần chờ đợi unsorted chunks 
  đã được xử lý để tìm thấy cái phù hợp nhất. Nhưng với yêu cầu nhỏ, kích thước luôn chính xác
   , vì thế chúng ta cần kiểm tra ngay bây giờ, và sẽ nhanh hơn)
   */

  if (in_smallbin_range (nb)) // Kiểm tra kích thước cấp phát có thuộc smallbins không < 0x400
    {
      idx = smallbin_index (nb); // Lấy idx tương ứng size (smallbins idx bắt đầu từ 2, idx = nb >> 4: 64 bit)
      bin = bin_at (av, idx); // Lấy địa chỉ bin chuẩn tương ứng idx

      if ((victim = last (bin)) != bin) // Gỡ chunk ra khỏi bins
        {
          bck = victim->bk;
      	  if (__glibc_unlikely (bck->fd != victim))  // Kiểm tra bins có bị thay đổi không
      	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb); // set bit PREV_INUSE chunk sau thành 0 (chunk trước free)
          bin->bk = bck;  // Cập nhập lại bin
          bck->fd = bin;

          if (av != &main_arena) // Check av có thuộc arena khác không
           set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);  // Check PREV_INUSE (khi MALLOC_DEBUG bật)
#if USE_TCACHE // Khi USE_TCACHE bật
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
    /* Khi cờ này được bật, nếu có chunks khác cùng size, đưa nó vào tcache */
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
          void *p = chunk2mem (victim);  // convert lại data và trả về địa chỉ chunk
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
  /* Nếu đây là một yêu cầu lớn, hợp nhất fastbins trước khi tiếp tục.
  Trong khi việc dọn sạch fastbins trước khi kiểm tra không gian khả dụng có vẻ quá mức,
  Điều đó tránh sự phân mảnh với fastbins, trong thực tế, chương trình có xu hướng chạy với yêu cầu nhỏ hoặc lớn
  nhưng ít trộn lẫn cả 2, vì vậy hành động hợp nhất nó không
  xảy ra thường xuyên với mọi chương trình. Và chương trình
  đó sẽ gọi thường xuyên cũng dẫn tới phân mảnh */

  else // Không thuộc fastbins và smallbins
    {
      idx = largebin_index (nb); // Lấy idx (chia idx theo size nb)
      if (atomic_load_relaxed (&av->have_fastchunks)) // Tìm kiếm fastbins chưa consolidate
        malloc_consolidate (av); // consolidate
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
  /* xử lý free gần đây hoặc còn lại trong chunks, chỉ lấy 1 chunk
  nếu nó phù hợp nhất, hoặc nếu đó là yêu cầu nhỏ, lấy chunk dư từ lần tìm kiếm không phù hợp gần nhất.
  Những chunks duyệt qua sẽ đi vào các bins. Lưu ý bước này là nơi duy nhấy các chunks được đưa vào các bins

  vòng lặp bên ngoài là cần thiết bởi vì chúng ta không cần nhận ra cho đến khi đến cuối quá trình malloc thì chúng ra mới nhận ra cần hợp nhất
  vì vậy phải làm vậy và thử lại. nếu không làm vậy, chúng ta phải mở rộng bộ nhớ để đáp ứng mỗi yêu cầu nhỏ */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb); // tính tc_idx
  if (tcache && tc_idx < mp_.tcache_bins) // Nếu tc_idx < max tcache bins
    tcache_nb = nb; // tcache_nb sẽ bằng size hiện tại
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; ) 
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)) // chunk av phải khác chunk sau
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size); // chunk tiếp theo

          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");  // size quá nhỏ hoặc quá lớn
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");  // size next chunk quá nhỏ hoặc quá lớn
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");  // prev_size chunk sau khác kích thước chunk hiện tại
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");  // fd của next chunk không phải chunk hiện tại
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");  // PREV_INUSE next chunk không khớp với tình trạng chunk hiện tại

          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */
          /* Nếu là yêu cầu nhỏ, thử sử dụng những chunk cuối cùng nếu nó là chunk duy nhất trong unsorted bin. 
          Điều này tăng tính cục bộ với những yêu cầu nhỏ liên tiếp. Đây là ngoại lệ để tìm kiếm chunk phù hợp nhất, 
          Quy tắc áp dụng khi không có chunk nào vừa khít hoàn toàn cho yêu cầu nhỏ */

          if (in_smallbin_range (nb) &&  // Kiểm tra xem nb có nhỏ hơn MAX_SMALL_SIZE không
              bck == unsorted_chunks (av) &&  // Kiểm tra xem chunk sau có phải là unsorted_chunks gốc không (nếu đúng thì unsorted bin có đúng 1 chunk)
              victim == av->last_remainder &&  // Kiểm tra victim là last_remainder không
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))  // Kích thước chunk > kích thước cần cấp phát + kích thước nhỏ nhất
            {
              /* split and reattach remainder */ // tách ra và gắn lại phần còn lại
              remainder_size = size - nb;  //size còn lại của chunk sau khi lấy 1 phần cấp phát
              remainder = chunk_at_offset (victim, nb);  // Chunk mới với size còn lại sau cấp phát
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;  // Đưa remainder làm chunk duy nhất trong unsorted bin 
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))  // Nếu kích thước chunk còn lại không nhỏ hơn MIN_LARGE_SIZE
                {
                  remainder->fd_nextsize = NULL;  // fd, bk = NULL, để đưa vào largebin và quản lý theo largebin
                  remainder->bk_nextsize = NULL;
                }

              set_head (victim, nb | PREV_INUSE |  // Set PREV_INUSE, kiểm tra chunk có thuộc main arena không, 
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);  // size chunk còn lại = remainder_size
              set_foot (remainder, remainder_size);  //  Chunk sau (có thể là head) prev_size phải bằng chunk remainder

              check_malloced_chunk (av, victim, nb); // Kiểm tra chung
              void *p = chunk2mem (victim);  // con trỏ p là địa chỉ chunk trả về 
              alloc_perturb (p, bytes);  // convert data
              return p;
            }

          /* remove from unsorted list */  // di chuyển từ danh sách unsorted
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");  // fd của chunk sau lại khác chunk trước
          unsorted_chunks (av)->bk = bck;  // Thay đổi head -> chunk sau của chunk victim
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */  // Nếu phù hợp thì lấy ngay

          if (size == nb)  // Nếu kích thước cần bằng kích thước chunk
            {
              set_inuse_bit_at_offset (victim, size);  // Thay đổi PREV_SIZE chunk sau
              if (av != &main_arena)  // av không phải main_arena
		            set_non_main_arena (victim);
#if USE_TCACHE 
      	      /* Fill cache first, return to user only if cache fills.
      		 We may return one of these chunks later.  */
              /* Lấp đầy tcache, trả về cho người dùng nếu tcache đầy, sau này chúng ta có thể trả về 1 trong những chunk đó */
      	      if (tcache_nb
            		  && tcache->counts[tc_idx] < mp_.tcache_count)  // Nếu size thuộc quản lý tcache và chunk trong tcache còn trống
            		{
            		  tcache_put (victim, tc_idx);  // Đưa chunk đó vào tcache
            		  return_cached = 1;
            		  continue;
      		      }
      	      else
      	       	{   
#endif
              check_malloced_chunk (av, victim, nb);  // Kiểm tra lại
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);  // convert lại data
              return p;
#if USE_TCACHE
	             	}
#endif
            }

          /* place chunk in bin */  // vị trí chunk trong bin

          if (in_smallbin_range (size))  // size trong phạm vi smallbin
            {
              victim_index = smallbin_index (size);  // Lấy idx
              bck = bin_at (av, victim_index); 
              fwd = bck->fd;  // chunk đầu tiên
            }
          else
            {
              victim_index = largebin_index (size);  // Không thuộc smallbin thì là largebin
              bck = bin_at (av, victim_index);
              fwd = bck->fd;  // chunk đầu tiên

              /* maintain large bins in sorted order */  // Xắp xếp large bins
              if (fwd != bck)  // Nếu chunk đầu tiên khác head --> bin này có chunk
                {
                  /* Or with inuse bit to speed comparisons */ // OR với bit inuse để tăng tốc độ so sánh
                  size |= PREV_INUSE;  // set bit PREV_INUSE
                  /* if smaller than smallest, bypass loop below */  // Nếu nhỏ hơn cái nhỏ nhất, bỏ qua vòng lặp dưới
                  assert (chunk_main_arena (bck->bk));  // Kiểm tra chunk phải nằm trong arena quản lý
                  if ((unsigned long) (size)  // Nếu size nhỏ hơn size chunk đầu tiên trong bin
		                  < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;  // Đổi vị trí fwd và bck, fwd giờ chính là head
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;  // Đưa victim vào sau fwd (head), nghĩa là làm chunk đầu tiên
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      while ((unsigned long) size < chunksize_nomask (fwd))  // Vòng lặp tìm vị trí mà size victim >= fwd
                        {
                          fwd = fwd->fd_nextsize;
			                    assert (chunk_main_arena (fwd));
                        }

                      if ((unsigned long) size
			                    == (unsigned long) chunksize_nomask (fwd))  // case victim = fwd thì xếp victim sau fwd
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;  // fwd này sẽ là vị trí chunk thứ 2 có size = victim
                      else  // victim > fwd thì thêm victim vào trước fwd
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");  // check thay đổi của danh sách liên kết đôi
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");  // check thay đổi trong danh sách liên kết đôi
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;  // Nếu trong large bin chưa có chunk nào thì victim chính là chunk đầu tiên
            }  // --> Ta có thể thấy trong large bin kích thước size sắp xếp theo thứ tự tăng dần

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
	       filling the cache, return one of the cached ones.  */
      /* Nếu trong quá trình xửa lý mà đầy tcache, trả về 1 trong số chunk trong tcache */
      ++tcache_unsorted_count;
      if (return_cached  // Nếu có chunk được từ unsorted bin đưa vào tcache
      	  && mp_.tcache_unsorted_limit > 0  // Chunk tồn tại
      	  && tcache_unsorted_count > mp_.tcache_unsorted_limit)  // chunk đưa vào tcache vượt qua giới hạn tcache
      	{
      	  return tcache_get (tc_idx);  // Trả 1 chunk từ tcache
      	}
#endif

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      /* Nếu tất cả chunk nhỏ được đưa vào tcache, trả ngay 1 chunk trong tcache */
      if (return_cached)  // Có chunk đưa vào tcache
      	{
      	  return tcache_get (tc_idx);  // Trả về chunk trong tcache
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