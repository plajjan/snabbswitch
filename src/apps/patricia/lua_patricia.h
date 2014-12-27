
typedef uint32_t in_addr_t;
struct in_addr {
	in_addr_t s_addr;
};
struct in6_addr {
	union
	{
		uint8_t __u6_addr8[16];
	} __in6_u;
};


typedef void (*void_fn_t)();
typedef struct _prefix4_t {
    unsigned short int family;		/* AF_INET | AF_INET6 */
    unsigned short int bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    struct in_addr sin;
} prefix4_t;

typedef struct _prefix_t {
    unsigned short int family;		/* AF_INET | AF_INET6 */
    unsigned short int bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    union {
		struct in_addr sin;
		struct in6_addr sin6;
    } add;
} prefix_t;

typedef struct _patricia_node_t {
   unsigned int bit;			/* flag if this node used */
   prefix_t *prefix;		/* who we are in patricia tree */
   struct _patricia_node_t *l, *r;	/* left and right children */
   struct _patricia_node_t *parent;/* may be used */
   void *data;			/* pointer to data */
   void	*user1;			/* pointer to usr data (ex. route flap info) */
   unsigned long int *block_until;

} patricia_node_t;

typedef struct _patricia_tree_t {
   patricia_node_t 	*head;
   unsigned int		maxbits;	/* for IP, 32 bit addresses */
   int num_active_node;		/* for debug purpose */
} patricia_tree_t;


patricia_node_t *patricia_search_exact (patricia_tree_t *patricia, prefix_t *prefix);
patricia_node_t *patricia_search_best (patricia_tree_t *patricia, prefix_t *prefix);
patricia_node_t * patricia_search_best2 (patricia_tree_t *patricia, prefix_t *prefix, 
				   int inclusive);
patricia_node_t *patricia_lookup (patricia_tree_t *patricia, prefix_t *prefix);
void patricia_remove (patricia_tree_t *patricia, patricia_node_t *node);
patricia_tree_t *New_Patricia (int maxbits);
void Clear_Patricia (patricia_tree_t *patricia, void_fn_t func);
void Destroy_Patricia (patricia_tree_t *patricia, void_fn_t func);

void patricia_process (patricia_tree_t *patricia, void_fn_t func);

char *prefix_toa (prefix_t * prefix);

prefix_t * ascii2prefix (int family, char *string);

patricia_node_t * make_and_lookup (patricia_tree_t *tree, char *string);

prefix_t * New_Prefix2 (int family, void *dest, int bitlen, prefix_t *prefix);

patricia_node_t * patricia_search_best (patricia_tree_t *patricia, prefix_t *prefix);

patricia_node_t * try_search_best (patricia_tree_t *tree, char *string);

patricia_node_t * search_best (patricia_tree_t *tree, unsigned int string);
