#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define max(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a > _b ? _a : _b;      \
    })
////////////////////////////////////////////////////////////////////////////////////
struct ENTRY {
    unsigned int nexthop;
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned char src_len;
    unsigned char dst_len;
    unsigned int src_port;  // short + short
    unsigned int dst_port;
    unsigned short protocol;  // char + char
    struct ENTRY *next;
};
////////////////////////////////////////////////////////////////////////////////////
static __inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}
////////////////////////////////////////////////////////////////////////////////////
struct bt_node {  // structure of binary trie
    unsigned int port;
    unsigned int num;
    struct bt_node *left, *right;
};
struct port_root {
    int num;  // num of child
    struct bt_node *child;
};
struct classifier {
    int dim;
    unsigned int np;
    void **child;
    int *num_child;
};
////////////////////////////////////////////////////////////////////////////////////
/*global variables*/
int num_entry = 0;
unsigned int num_query = 0;
struct ENTRY *table, *query;
int N = 0;  // number of nodes
unsigned long long int begin, end, total = 0;
unsigned long long int *my_clock;
int num_node = 0;  // total number of rule in linked list
int num_clsr = 1;  // total number of classifier
#ifdef BINTH
int binth = BINTH;
#else
int binth = 100;
#endif

#ifndef SPFAC
#define SPFAC 8
#endif

struct classifier *root;
////////////////////////////////////////////////////////////////////////////////////
struct bt_node *create_node()
{
    struct bt_node *temp;
    temp = (struct bt_node *) malloc(sizeof(struct bt_node));
    temp->right = NULL;
    temp->left = NULL;
    temp->port = 256;  // default port
    temp->num = 0;
    return temp;
}
////////////////////////////////////////////////////////////////////////////////////
void add_bt_node(struct bt_node *ptr,
                 unsigned int ip,
                 unsigned char len,
                 unsigned char nexthop)
{
    int i;
    for (i = 0; i < len; i++) {
        if (ip & (1 << (31 - i))) {
            if (ptr->right == NULL)
                ptr->right = create_node();  // Create Node
            ptr = ptr->right;
            if (i == len - 1) {
                ptr->port = nexthop;
                ptr->num += 1;
            }

        } else {
            if (ptr->left == NULL)
                ptr->left = create_node();
            ptr = ptr->left;
            if (i == len - 1) {
                ptr->port = nexthop;
                ptr->num += 1;
            }
        }
    }
}
////////////////////////////////////////////////////////////////////////////////////
void read_table(char *str, struct ENTRY *node)
{
    char tok[] = "./\t:";
    char buf[100], *str1;
    unsigned int n[4];
    sprintf(buf, "%s", strtok(++str, tok));  // ignore @
    n[0] = atoi(buf);
    int i;
    for (i = 1; i < 4; i++) {
        sprintf(buf, "%s", strtok(NULL, tok));
        n[i] = atoi(buf);
    }
    node->nexthop = n[2];
    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->src_len = atoi(buf);
    node->src_ip = (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];

    for (i = 0; i < 4; i++) {
        sprintf(buf, "%s", strtok(NULL, tok));
        n[i] = atoi(buf);
    }
    node->dst_ip = (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_len = atoi(buf);

    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->src_port = atoi(buf) << 16;

    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->src_port += atoi(buf);

    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_port = atoi(buf) << 16;

    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->dst_port += atoi(buf);

    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->protocol = strtoul(buf, NULL, 0) << 8;

    str1 = (char *) strtok(NULL, tok);
    sprintf(buf, "%s", str1);
    node->protocol += strtoul(buf, NULL, 0);
}
////////////////////////////////////////////////////////////////////////////////////
int search(struct ENTRY *node)
{
    int index;
    struct classifier *current = root;
    struct ENTRY *tmp;
    while (current) {
        switch (current->dim) {
        case (1):
            index = node->src_ip >> (32 - (int) log2(current->np));
            break;
        case (2):
            index = node->dst_ip >> (32 - (int) log2(current->np));
            break;
        case (3):
            index = (node->src_port >> 16) / (65536 / current->np);
            break;
        case (4):
            index = (node->dst_port >> 16) / (65536 / current->np);
            break;
        case (5):
            index = node->protocol / (65536 / current->np);
            break;
        }
        if (current->child[index] == NULL) {
            // Not Found
            return 0;
        } else if (current->num_child[index] == 0) {
            // next classifier
            current = (struct classifier *) current->child[index];
        } else {  // TODO Make search more correctly
            for (tmp = (struct ENTRY *) (current->child[index]); tmp;
                 tmp = tmp->next) {
                if (node->src_ip == tmp->src_ip &&
                    node->dst_ip == tmp->dst_ip &&
                    node->src_port == tmp->src_port &&
                    node->dst_port == tmp->dst_port)
                    return 1;
            }
            return 0;
        }
    }

    return 0;
    /*for (j = 31; j >= (-1); j--) {
        if (current == NULL)
            break;
        if (current->port != 256)
            temp = current;
        if (ip & (1 << j)) {
            current = current->right;
        } else {
            current = current->left;
        }
    }*/

    /*if(temp==NULL)
      printf("default\n");
      else
      printf("%u\n",temp->port);*/
}
////////////////////////////////////////////////////////////////////////////////////
void set_table(char *file_name)
{
    FILE *fp;
    char string[200];
    fp = fopen(file_name, "r");
    while (fgets(string, 200, fp) != NULL) {
        num_entry++;
    }
    rewind(fp);
    table = (struct ENTRY *) malloc(num_entry * sizeof(struct ENTRY));
    num_entry = 0;
    while (fgets(string, 200, fp) != NULL) {
        read_table(string, &table[num_entry]);
        table[num_entry].next = NULL;
        num_entry++;
    }
    fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////////
void set_query(char *file_name)
{
    FILE *fp;
    char string[100];
    fp = fopen(file_name, "r");
    while (fgets(string, 200, fp) != NULL) {
        num_query++;
    }
    rewind(fp);
    query = (struct ENTRY *) malloc(num_query * sizeof(struct ENTRY));
    my_clock = (unsigned long long int *) malloc(num_query *
                                              sizeof(unsigned long long int));
    num_query = 0;
    while (fgets(string, 200, fp) != NULL) {
        read_table(string, &query[num_query]);
        query[num_query].next = NULL;
        my_clock[num_query++] = 10000000;
    }
    fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////////
void count_distinct_node(struct bt_node *ptr)
{
    if (ptr == NULL) {
        return;
    }
    count_distinct_node(ptr->left);
    if (ptr->port != 256) {
        N++;
    }
    count_distinct_node(ptr->right);
}
////////////////////////////////////////////////////////////////////////////////////
void add_port_node(struct port_root *begin, unsigned int end)
{
    if (begin->child == NULL) {
        begin->child = (struct bt_node *) malloc(sizeof(struct bt_node));
        begin->child->port = end;
        begin->child->left = NULL;
        begin->child->right = NULL;
        begin->num = 1;
        return;
    }
    struct bt_node *now, *new_node;
    new_node = (struct bt_node *) malloc(sizeof(struct bt_node));
    new_node->port = end;
    new_node->left = NULL;
    new_node->right = NULL;
    new_node->num = 1;
    now = begin->child;
    while (now) {
        if (end > now->port) {
            if (now->right == NULL) {
                now->right = new_node;
                begin->num++;
                return;
            } else {
                now = now->right;
            }
        } else if (end < now->port) {
            if (now->left == NULL) {
                now->left = new_node;
                begin->num++;
                return;
            } else {
                now = now->left;
            }
        } else {
            free(new_node);
            now->num += 1;
            return;
        }
    }
}
////////////////////////////////////////////////////////////////////////////////////
int child_partition;
void count_partition(struct bt_node *ptr, unsigned int np, int layer)
{
    if (!ptr)
        return;
    if (layer < 33 && layer <= log2(np)) {
        child_partition += np / pow(2, layer - 1) * ptr->num;
    } else {
        child_partition += ptr->num;
    }
    count_partition(ptr->left, np, layer + 1);
    count_partition(ptr->right, np, layer + 1);
}
////////////////////////////////////////////////////////////////////////////////////
unsigned int pick_np(int dimension, int num_rule, struct ENTRY *node)
{
    int spfac = SPFAC;
    int spmf = num_rule * spfac;
    int sm = 0;
    int np = 1;
    struct ENTRY *now;
    while (sm < spmf) {
        sm = 0;
        np *= 2;
        switch (dimension) {
        case (1):
            for (now = node; now; now = now->next) {
                if (now->src_len < log2(np)) {
                    sm += np / (pow(2, (now->src_len)));
                } else {
                    sm += 1;
                }
            }
            break;
        case (2):
            for (now = node; now; now = now->next) {
                if (now->dst_len < log2(np)) {
                    sm += np / (pow(2, (now->dst_len)));
                } else {
                    sm += 1;
                }
            }
            break;
        case (3):
            for (now = node; now; now = now->next) {
                sm += (((now->src_port & 0xffff) - (now->src_port >> 16)) /
                       (65536 / np)) +
                      1;
            }
            break;
        case (4):
            for (now = node; now; now = now->next) {
                sm += (((now->dst_port & 0xffff) - (now->dst_port >> 16)) /
                       (65536 / np)) +
                      1;
            }
            break;
        case (5):
            sm += num_rule;
            break;
        default:
            printf("wtf? dim: %d\n", dimension);
            exit(1);
        }
        sm += np;
        if (dimension > 2 && np == 65536) {
            break;
        }
    }
    return np;
}
void free_bt_tree(struct bt_node *node)
{
    if (node == NULL) {
        return;
    }
    free_bt_tree(node->left);
    free_bt_tree(node->right);
    free(node);
}
void free_port_tree(struct port_root *node)
{
    int i;
    for (i = 0; i < 65536; i++) {
        free_bt_tree(node[i].child);
        /*if (node[i].child) {
            free_bt_tree(node[i].child->left);
            free_bt_tree(node[i].child->right);
            free(node[i].child);
        }*/
    }
    free(node);
}
////////////////////////////////////////////////////////////////////////////////////
void pick(struct ENTRY *node_rule,
          int num_rule,
          int *dimension,
          unsigned int *np)
{
    ///////// pick dimension
    int i;
    struct bt_node *src_ip_root, *dst_ip_root;
    struct port_root *src_port_begin, *dst_port_begin;
    int proto[65536] = {};
    int num_src_ip = 0, num_dst_ip = 0;
    int num_src_port = 0, num_dst_port = 0;
    int num_protocol = 0;
    struct ENTRY *tmp;

    src_ip_root = create_node();
    dst_ip_root = create_node();
    src_port_begin =
        (struct port_root *) malloc(sizeof(struct port_root) * 65536);
    dst_port_begin =
        (struct port_root *) malloc(sizeof(struct port_root) * 65536);
    memset(src_port_begin, '\0', sizeof(struct port_root) * 65536);
    memset(dst_port_begin, '\0', sizeof(struct port_root) * 65536);
    for (tmp = node_rule; tmp; tmp = tmp->next) {
        // create binary tree of src. ip
        add_bt_node(src_ip_root, tmp->src_ip, tmp->src_len, tmp->nexthop);
        // create binary tree of dst. ip
        add_bt_node(dst_ip_root, tmp->dst_ip, tmp->dst_len, tmp->nexthop);
        // create binary trie of src. port
        add_port_node(&src_port_begin[tmp->src_port >> 16],
                      tmp->src_port & 0xffff);
        // create binary trie of dst. port
        add_port_node(&dst_port_begin[tmp->dst_port >> 16],
                      tmp->dst_port & 0xffff);
        // count number of distinct protocol
        proto[tmp->protocol] += 1;
    }

    // count distinct node of src. ip
    N = 0;
    count_distinct_node(src_ip_root);
    num_src_ip = N;

    // count distinct node of dst. ip
    N = 0;
    count_distinct_node(dst_ip_root);
    num_dst_ip = N;

    for (i = 0; i < 65536; i++) {
        num_src_port += src_port_begin[i].num;
        num_dst_port += dst_port_begin[i].num;
        num_protocol += (proto[i] > 0) ? 1 : 0;
    }

    // compare 5 axis
    *dimension = 1;
    int max_num = num_src_ip;
    if (num_dst_ip > max_num) {
        *dimension = 2;
        max_num = num_dst_ip;
    }
    if (num_src_port > max_num) {
        *dimension = 3;
        max_num = num_src_port;
    }
    if (num_dst_port > max_num) {
        *dimension = 4;
        max_num = num_dst_port;
    }
    if (num_protocol > max_num) {
        *dimension = 5;
    }
    // free other
    free_bt_tree(src_ip_root);
    free_bt_tree(dst_ip_root);
    free_port_tree(src_port_begin);
    free_port_tree(dst_port_begin);


    ////// pick np
    *np = pick_np(*dimension, num_rule, node_rule);
}

////////////////////////////////////////////////////////////////////////////////////

void classify(struct ENTRY *node, struct classifier *clsr)
{
    unsigned int index = 0;
    int i, copy_time;
    if (clsr->dim < 3) {
        // cut prefix
        unsigned int ip = (clsr->dim == 1) ? node->src_ip : node->dst_ip;
        unsigned char len = (clsr->dim == 1) ? node->src_len : node->dst_len;
        index = ip >> (32 - (int) log2(clsr->np));

        // duplicate
        if ((log2(clsr->np) - len) > 0)
            copy_time = clsr->np / pow(2, len);
        else
            copy_time = 1;
    } else if (clsr->dim < 5) {
        // cut port
        unsigned int port_begin =
            (clsr->dim == 3) ? node->src_port >> 16 : node->dst_port >> 16;
        unsigned int port_end = (clsr->dim == 3) ? node->src_port & 0xffff
                                                 : node->dst_port & 0xffff;

        if (clsr->np > 65536) {
            printf("np too big: %u\n", clsr->np);
            clsr->np = 65536;
        }
        copy_time = (port_end / (65536 / clsr->np)) -
                    (port_begin / (65536 / clsr->np)) + 1;
        index = port_begin / (65536 / clsr->np);
    } else if (clsr->dim == 5) {
        if (clsr->np > 65536) {
            clsr->np = 65536;
        }
        index = node->protocol / (65536 / clsr->np);
        copy_time = 1;
    } else {
        printf("dimension error\n");
        exit(1);
    }

    for (i = 0; i < copy_time; i++) {
        struct ENTRY *new_node;
        new_node = (struct ENTRY *) malloc(sizeof(struct ENTRY));
        memcpy(new_node, node, sizeof(struct ENTRY));
        new_node->next = (struct ENTRY *) clsr->child[index + i];
        clsr->child[index + i] = new_node;
        clsr->num_child[index + i] += 1;
        num_node++;
    }
}
void *cut(struct ENTRY *node, int num_rule)
{  // or void* ?

    //printf("cut %d\n", num_rule);
    // let rule to array
    struct ENTRY *new_table, *tmp;
    struct classifier *new_clsr;
    unsigned int i;
    new_clsr = (struct classifier *) malloc(sizeof(struct classifier));
    if (root == NULL) {  // first cut
        root = new_clsr;
        struct ENTRY *new_node;
        new_node = (struct ENTRY *) malloc(sizeof(struct ENTRY));
        memcpy(new_node, &node[0], sizeof(struct ENTRY));
        new_table = new_node;
        tmp = new_node;
        new_node = NULL;

        for (i = 1; i < (unsigned int) num_rule; i++) {
            new_node = (struct ENTRY *) malloc(sizeof(struct ENTRY));
            memcpy(new_node, &node[i], sizeof(struct ENTRY));
            tmp->next = new_node;
            tmp = new_node;
            new_node = NULL;
        }
        free(table);
    } else {
        new_table = node;
    }

    pick(new_table, num_rule, &(new_clsr->dim), &(new_clsr->np));
    /*printf("np: %u\n", new_clsr->np);*/
    // printf("dimension: %d\n", new_clsr->dim);
    new_clsr->child = (void **) malloc(sizeof(struct ENTRY *) * new_clsr->np);

    // memset(new_clsr->child, '\0', sizeof(struct ENTRY *) * new_clsr->np);
    new_clsr->num_child = (int *) malloc(sizeof(int) * new_clsr->np);
    for (i = 0; i < new_clsr->np; i++) {
        new_clsr->child[i] = NULL;
        new_clsr->num_child[i] = 0;
    }
    while (new_table) {
        tmp = new_table;
        classify(new_table, new_clsr);
        new_table = new_table->next;
        free(tmp);
    }
    /*for (i = 0; i < new_clsr->np; i++) {*/
    /*printf("%d ", new_clsr->num_child[i]);*/
    /*}*/

    for (i = 0; i < new_clsr->np; i++) {
        if (new_clsr->num_child[i] > binth &&
            new_clsr->num_child[i] < num_rule) {
            new_clsr->child[i] = (void *) cut(
                (struct ENTRY *) new_clsr->child[i], new_clsr->num_child[i]);
#ifdef cut
            printf("new_cut: dim: %d, rules: %d, ori_rules: %d\n",
                   ((struct classifier *) (new_clsr->child[i]))->dim,
                   new_clsr->num_child[i], num_rule);
#endif
            new_clsr->num_child[i] = 0;
            num_clsr++;
        }
    }
    return new_clsr;
}
////////////////////////////////////////////////////////////////////////////////////
void count_node(struct bt_node *r)
{
    if (r == NULL)
        return;
    count_node(r->left);
    N++;
    count_node(r->right);
}
////////////////////////////////////////////////////////////////////////////////////
void CountClock()
{
    unsigned int i;
    unsigned int *NumCntClock =
        (unsigned int *) malloc(50 * sizeof(unsigned int));
    for (i = 0; i < 50; i++)
        NumCntClock[i] = 0;
    unsigned long long MinClock = 10000000, MaxClock = 0;
    for (i = 0; i < num_query; i++) {
        if (my_clock[i] > MaxClock)
            MaxClock = my_clock[i];
        if (my_clock[i] < MinClock)
            MinClock = my_clock[i];
        if (my_clock[i] / 100 < 50)
            NumCntClock[my_clock[i] / 100]++;
        else
            NumCntClock[49]++;
    }
    printf("(MaxClock, MinClock) =\t(%5llu, %5llu)\n", MaxClock, MinClock);

    /*for (i = 0; i < 50; i++) {
        printf("%f\n", (double)NumCntClock[i]/num_entry);
    }*/
    return;
}

void shuffle(struct ENTRY *array, int n)
{
    srand((unsigned) time(NULL));
    struct ENTRY *temp = (struct ENTRY *) malloc(sizeof(struct ENTRY));

    int i;
    for (i = 0; i < n - 1; i++) {
        size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
        memcpy(temp, &array[j], sizeof(struct ENTRY));
        memcpy(&array[j], &array[i], sizeof(struct ENTRY));
        memcpy(&array[i], temp, sizeof(struct ENTRY));
    }
}
void free_classifier(struct classifier *node)
{
    if (node == NULL) {
        return;
    }
    struct ENTRY *tmp, *for_free;
    unsigned int i;
    for (i = 0; i < node->np; i++) {
        if (node->num_child[i] == 0) {
            free_classifier((struct classifier *) node->child[i]);
        } else if (node->child[i]) {
            tmp = (struct ENTRY *) (node->child[i]);
            while (tmp) {
                for_free = tmp;
                tmp = tmp->next;
                for_free->next = NULL;
                free(for_free);
            }
        }
    }
    free(node->child);
    free(node->num_child);
    free(node);
}
////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Please execute the file as the following way:\n");
        printf("%s  routing_table_file_name  query_table_file_name\n",argv[0]);
        exit(1);
    }
    unsigned int i, j;
    // set_query(argv[2]);
    // set_table(argv[1]);
    set_query(argv[1]);
    set_table(argv[1]);
    begin = rdtsc();
    cut(table, num_entry);
    end = rdtsc();
    printf("Avg. Insert:\t%llu\n", (end - begin) / num_entry);

    // shuffle(query, num_entry);
    ////////////////////////////////////////////////////////////////////////////
    for (j = 0; j < 100; j++) {
        for (i = 0; i < num_query; i++) {
            begin = rdtsc();
            if (search(&query[i]) == 0) {
                printf("Not Found %d\n", i);
                exit(1);
            }
            end = rdtsc();
            if (my_clock[i] > (end - begin))
                my_clock[i] = (end - begin);
        }
    }
    total = 0;
    for (j = 0; j < num_query; j++)
        total += my_clock[j];
    printf("Avg. Search:\t%llu\n", total / num_query);
    printf("number of nodes:\t%d\n", num_node);
    printf("Total memory requirement:\t%ld KB\n",
           ((num_node * sizeof(struct ENTRY) +
             num_clsr * sizeof(struct classifier)) /
            1024));
    CountClock();
    ////////////////////////////////////////////////////////////////////////////
    // count_node(root);
    // printf("There are %d nodes in binary trie\n",N);
    free_classifier(root);
    free(query);
    free(my_clock);
    return 0;
}
