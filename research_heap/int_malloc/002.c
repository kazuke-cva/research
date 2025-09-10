/* Check if REQ overflows when padded and aligned and if the resulting value
   is less than PTRDIFF_T.  Returns TRUE and the requested size or MINSIZE in
   case the value is less than MINSIZE on SZ or false if any of the previous
   check fail.  */ 
// kiểm tra REQ có bị tràn khi đệm, căn chỉnh và nếu giá trị trả về nhỏ hơn PTRDIFF_T thì trả về TRUE và yêu cầu về kích thước hoặc MINSIZE trong trường hợp giá trị nhỏ hơn MINSIZE
// trên SZ hoặc FALSE nếu bất kì kiểm tra trước đó lỗi
static inline bool
checked_request2size (size_t req, size_t *sz) __nonnull (1) // Tham số không được null
{
  if (__glibc_unlikely (req > PTRDIFF_MAX)) // req lớn hơn 0x7fffffffffffffff trả về FALSE
    return false; 

# if __WORDSIZE == 64
#  define PTRDIFF_MAX   (9223372036854775807L)
# else
#  if __WORDSIZE32_PTRDIFF_LONG
#   define PTRDIFF_MAX    (2147483647L)
#  else
#   define PTRDIFF_MAX    (2147483647)

  /* When using tagged memory, we cannot share the end of the user
     block with the header for the next chunk, so ensure that we
     allocate blocks that are rounded up to the granule size.  Take
     care not to overflow from close to MAX_SIZE_T to a small
     number.  Ideally, this would be part of request2size(), but that
     must be a macro that produces a compile time constant if passed
     a constant literal.  */
// 

/*  Khi sử dụng bộ nhớ gắn thẻ(tagged memory), chúng ta không thể dùng chung phần cuối khối người dùng với tiêu đề (header) chunk tiếp theo
    Vì vậy đảm bảo rằng các khối được cấp phát sẽ làm tròn lên theo kích thước granule
    Tránh các trường hợp overflow khi giá trị gần MAX_SIZE_T quay vòng về con số nhỏ
    lý tưởng thì đoạn xử lý sẽ là phần của request2size(), nhưng hàm đó phải là macro tạo ra hằng số tại thời điểm biên dịch nếu tham số truyền vào là 1 giá trị hằng */
  if (__glibc_unlikely (mtag_enabled)) // Nếu mtag_enabled bật thì mới thực hiện cái này
    {
      /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
      /* Đảm bảo rằng cái này không phải là evaluated nếu mtag_enabled không bật */
      asm ("");

      req = (req + (__MTAG_GRANULE_SIZE - 1)) &  // Cái này để làm tròn lên theo kích thước GRANULE
	    ~(size_t)(__MTAG_GRANULE_SIZE - 1);
    }

#define __MTAG_GRANULE_SIZE 1

  *sz = request2size (req); // Chuẩn hóa size yêu cầu thành size để malloc cấp phát
  return true;

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* req là kích thước ta yêu cầu
SIZE_SZ là kích thước phần metadata */
#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T)) // Ta có thể thấy SIZE_SZ được khai báo theo  kích thước INTERNAL_SIZE_T, mà INTERNAL_SIZE_T được khai báo theo size_t, size_t sẽ là 4 byte trên hệ thống 32 bit và 8 byte trên hệ thống 64 bit
// MALLOC_ALIGN_MASK đảm bảo chunk được align then chuẩn kiến trúc, chẳng hạn kiến trúc x86_64, thì SIZE_SZ = 8, --> MALLOC_ALIGNMENT = 16 --> MALLOC_ALIGN_MASK = 15
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
        ? __alignof__ (long double) : 2 * SIZE_SZ)
// MINSIZE là kích thước chunk nhỏ nhất
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
/* MINSIZE lấy theo kích thước MIN_CHUNK_SIZE, mà MIN_CHUNK_SIZE lấy theo kích thước malloc_chunk tới fd_nextsize, ta xem struct malloc_chunk có kích thước
tổng là 48 byte, còn kích thước tới fd_nextsize là 32 byte --> MINSIZE = 0x20 byte */

/* Vậy ta có thể tính kích thước malloc cấp phát, chẳng hạn ta yêu cầu 1 byte, thì sẽ là: 1 + 8 + 15 = 24 < 0x20 --> cấp phát 0x20 byte
yêu cầu 18 byte: 18 + 8 + 15 = 41 > 0x20 --> cấp phát 41 & ~15 = 0x20 byte */
// *sz sẽ chứa kích thước cấp phát và hàm sẽ trả về TRUE
}

pp = REVEAL_PTR (victim->fd);
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
/* Sử dụng randomness từ ASLR tới bảo vệ danh sách liên kết đơn của Fast-Bín và Tcache. 
Cái này là con trỏ kế tiếp trong danh sách chunk, mà còn kiểm tra phân bổ trên chúng
Cơ chế này giảm bớt rủi ro tấn công con trỏ, bằng việc hoàn thành với Safe-Unlinking trên danh sách double-linked của Small-Bins
Nó cho rằng kích thước tối thiểu trang là 2096 bytes (12 bits). Hệ thống  với cung cấp trang lớn hơn entropy, mặc dù con trỏ vẫn làm hỏng từ */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))

/* REVEAL_PTR gọi PROTECT_PTR với con trỏ tới next chunk và địa chỉ con trỏ đấy, pos là địa chỉ con trỏ, ptr là giá trị con trỏ
, việc mã hóa bằng cách lấy 12 bit thấp (ASLR memory) để ^ với fd tạo ra con trỏ mã hóa, mà ở đây ta đang lấy con trỏ nên là giải mã */

/* offset 2 to use otherwise unindexable first 2 bins */
/* dịch chuyển thêm 2 để có thể sử dụng 2 bin đầu tiên vốn dĩ không thể đánh chỉ số. */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
// Lấy idx phù hợp với kích thước cấp phát
// Nghĩa là trong danh sách bin thì 2 bin đầu không thể đánh chỉ số nên phải dịch lên 2

typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];
// Đây là mảng fastbin theo kiểm malloc_chunk

/* addressing -- note that bin_at(0) does not exist */
/* Không tồn tại bin_at(0)(như đã nói thì smallbins idx bắt đầu từ 2) */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))           \ /* bins là mảng kiển malloc_chunk chứa fd, bk, ép kiểu về malloc_chunk lấy địa chỉ fd - offset để lấy địa chỉ chunk chuẩn */
             - offsetof (struct malloc_chunk, fd))