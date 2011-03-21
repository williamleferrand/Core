// S3 putobject 

#ifndef AWS_ACCESS_KEY
#define AWS_ACCESS_KEY "AKIA..."
#endif

#ifndef AWS_SECRET
#define AWS_SECRET "5mU..."
#endif

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <libs3.h>

// Some Windows stuff
#ifndef FOPEN_EXTRA_FLAGS
#define FOPEN_EXTRA_FLAGS ""
#endif


// Command-line options, saved as globals ------------------------------------

static int forceG = 0;
static int showResponsePropertiesG = 0;
static S3Protocol protocolG = S3ProtocolHTTPS;
static S3UriStyle uriStyleG = S3UriStylePath;
static int retriesG = 5;



// Request results, saved as globals -----------------------------------------

static int statusG = 0;
static char errorDetailsG[4096] = { 0 };


// Other globals -------------------------------------------------------------

static char putenvBufG[256];


#define LOCATION_PREFIX "location="
#define LOCATION_PREFIX_LEN (sizeof(LOCATION_PREFIX) - 1)
#define CANNED_ACL_PREFIX "cannedAcl="
#define CANNED_ACL_PREFIX_LEN (sizeof(CANNED_ACL_PREFIX) - 1)
#define PREFIX_PREFIX "prefix="
#define PREFIX_PREFIX_LEN (sizeof(PREFIX_PREFIX) - 1)
#define MARKER_PREFIX "marker="
#define MARKER_PREFIX_LEN (sizeof(MARKER_PREFIX) - 1)
#define DELIMITER_PREFIX "delimiter="
#define DELIMITER_PREFIX_LEN (sizeof(DELIMITER_PREFIX) - 1)
#define MAXKEYS_PREFIX "maxkeys="
#define MAXKEYS_PREFIX_LEN (sizeof(MAXKEYS_PREFIX) - 1)
#define FILENAME_PREFIX "filename="
#define FILENAME_PREFIX_LEN (sizeof(FILENAME_PREFIX) - 1)
#define CONTENT_LENGTH_PREFIX "contentLength="
#define CONTENT_LENGTH_PREFIX_LEN (sizeof(CONTENT_LENGTH_PREFIX) - 1)
#define CACHE_CONTROL_PREFIX "cacheControl="
#define CACHE_CONTROL_PREFIX_LEN (sizeof(CACHE_CONTROL_PREFIX) - 1)
#define CONTENT_TYPE_PREFIX "contentType="
#define CONTENT_TYPE_PREFIX_LEN (sizeof(CONTENT_TYPE_PREFIX) - 1)
#define MD5_PREFIX "md5="
#define MD5_PREFIX_LEN (sizeof(MD5_PREFIX) - 1)
#define CONTENT_DISPOSITION_FILENAME_PREFIX "contentDispositionFilename="
#define CONTENT_DISPOSITION_FILENAME_PREFIX_LEN \
    (sizeof(CONTENT_DISPOSITION_FILENAME_PREFIX) - 1)
#define CONTENT_ENCODING_PREFIX "contentEncoding="
#define CONTENT_ENCODING_PREFIX_LEN (sizeof(CONTENT_ENCODING_PREFIX) - 1)
#define EXPIRES_PREFIX "expires="
#define EXPIRES_PREFIX_LEN (sizeof(EXPIRES_PREFIX) - 1)
#define X_AMZ_META_PREFIX "x-amz-meta-"
#define X_AMZ_META_PREFIX_LEN (sizeof(X_AMZ_META_PREFIX) - 1)
#define IF_MODIFIED_SINCE_PREFIX "ifModifiedSince="
#define IF_MODIFIED_SINCE_PREFIX_LEN (sizeof(IF_MODIFIED_SINCE_PREFIX) - 1)
#define IF_NOT_MODIFIED_SINCE_PREFIX "ifNotmodifiedSince="
#define IF_NOT_MODIFIED_SINCE_PREFIX_LEN \
    (sizeof(IF_NOT_MODIFIED_SINCE_PREFIX) - 1)
#define IF_MATCH_PREFIX "ifMatch="
#define IF_MATCH_PREFIX_LEN (sizeof(IF_MATCH_PREFIX) - 1)
#define IF_NOT_MATCH_PREFIX "ifNotMatch="
#define IF_NOT_MATCH_PREFIX_LEN (sizeof(IF_NOT_MATCH_PREFIX) - 1)
#define START_BYTE_PREFIX "startByte="
#define START_BYTE_PREFIX_LEN (sizeof(START_BYTE_PREFIX) - 1)
#define BYTE_COUNT_PREFIX "byteCount="
#define BYTE_COUNT_PREFIX_LEN (sizeof(BYTE_COUNT_PREFIX) - 1)
#define ALL_DETAILS_PREFIX "allDetails="
#define ALL_DETAILS_PREFIX_LEN (sizeof(ALL_DETAILS_PREFIX) - 1)
#define NO_STATUS_PREFIX "noStatus="
#define NO_STATUS_PREFIX_LEN (sizeof(NO_STATUS_PREFIX) - 1)
#define RESOURCE_PREFIX "resource="
#define RESOURCE_PREFIX_LEN (sizeof(RESOURCE_PREFIX) - 1)
#define TARGET_BUCKET_PREFIX "targetBucket="
#define TARGET_BUCKET_PREFIX_LEN (sizeof(TARGET_BUCKET_PREFIX) - 1)
#define TARGET_PREFIX_PREFIX "targetPrefix="
#define TARGET_PREFIX_PREFIX_LEN (sizeof(TARGET_PREFIX_PREFIX) - 1)

typedef struct growbuffer
{
    // The total number of bytes, and the start byte
    int size;
    // The start byte
    int start;
    // The blocks
    char data[64 * 1024];
    struct growbuffer *prev, *next;
} growbuffer;


// returns nonzero on success, zero on out of memory
static int growbuffer_append(growbuffer **gb, const char *data, int dataLen)
{
    while (dataLen) {
        growbuffer *buf = *gb ? (*gb)->prev : 0;
        if (!buf || (buf->size == sizeof(buf->data))) {
            buf = (growbuffer *) malloc(sizeof(growbuffer));
            if (!buf) {
                return 0;
            }
            buf->size = 0;
            buf->start = 0;
            if (*gb) {
                buf->prev = (*gb)->prev;
                buf->next = *gb;
                (*gb)->prev->next = buf;
                (*gb)->prev = buf;
            }
            else {
                buf->prev = buf->next = buf;
                *gb = buf;
            }
        }

        int toCopy = (sizeof(buf->data) - buf->size);
        if (toCopy > dataLen) {
            toCopy = dataLen;
        }

        memcpy(&(buf->data[buf->size]), data, toCopy);
        
        buf->size += toCopy, data += toCopy, dataLen -= toCopy;
    }

    return 1;
}


static void growbuffer_read(growbuffer **gb, int amt, int *amtReturn, 
                            char *buffer)
{
    *amtReturn = 0;

    growbuffer *buf = *gb;

    if (!buf) {
        return;
    }

    *amtReturn = (buf->size > amt) ? amt : buf->size;

    memcpy(buffer, &(buf->data[buf->start]), *amtReturn);
    
    buf->start += *amtReturn, buf->size -= *amtReturn;

    if (buf->size == 0) {
        if (buf->next == buf) {
            *gb = 0;
        }
        else {
            *gb = buf->next;
        }
        free(buf);
    }
}


static void growbuffer_destroy(growbuffer *gb)
{
    growbuffer *start = gb;

    while (gb) {
        growbuffer *next = gb->next;
        free(gb);
        gb = (next == start) ? 0 : next;
    }
}


// Convenience utility for making the code look nicer.  Tests a string
// against a format; only the characters specified in the format are
// checked (i.e. if the string is longer than the format, the string still
// checks out ok).  Format characters are:
// d - is a digit
// anything else - is that character
// Returns nonzero the string checks out, zero if it does not.
static int checkString(const char *str, const char *format)
{
    while (*format) {
        if (*format == 'd') {
            if (!isdigit(*str)) {
                return 0;
            }
        }
        else if (*str != *format) {
            return 0;
        }
        str++, format++;
    }

    return 1;
}


static int64_t parseIso8601Time(const char *str)
{
    // Check to make sure that it has a valid format
    if (!checkString(str, "dddd-dd-ddTdd:dd:dd")) {
        return -1;
    }

#define nextnum() (((*str - '0') * 10) + (*(str + 1) - '0'))

    // Convert it
    struct tm stm;
    memset(&stm, 0, sizeof(stm));

    stm.tm_year = (nextnum() - 19) * 100;
    str += 2;
    stm.tm_year += nextnum();
    str += 3;

    stm.tm_mon = nextnum() - 1;
    str += 3;

    stm.tm_mday = nextnum();
    str += 3;

    stm.tm_hour = nextnum();
    str += 3;

    stm.tm_min = nextnum();
    str += 3;

    stm.tm_sec = nextnum();
    str += 2;

    stm.tm_isdst = -1;

    // This is hokey but it's the recommended way ...
    char *tz = getenv("TZ");
    snprintf(putenvBufG, sizeof(putenvBufG), "TZ=UTC");
    putenv(putenvBufG);

    int64_t ret = mktime(&stm);

    snprintf(putenvBufG, sizeof(putenvBufG), "TZ=%s", tz ? tz : "");
    putenv(putenvBufG);

    // Skip the millis

    if (*str == '.') {
        str++;
        while (isdigit(*str)) {
            str++;
        }
    }
    
    if (checkString(str, "-dd:dd") || checkString(str, "+dd:dd")) {
        int sign = (*str++ == '-') ? -1 : 1;
        int hours = nextnum();
        str += 3;
        int minutes = nextnum();
        ret += (-sign * (((hours * 60) + minutes) * 60));
    }
    // Else it should be Z to be a conformant time string, but we just assume
    // that it is rather than enforcing that

    return ret;
}


// Simple ACL format:  Lines of this format:
// Type - ignored
// Starting with a dash - ignored
// Email email_address permission
// UserID user_id (display_name) permission
// Group Authenticated AWS Users permission
// Group All Users  permission
// permission is one of READ, WRITE, READ_ACP, WRITE_ACP, FULL_CONTROL
static int convert_simple_acl(char *aclXml, char *ownerId,
                              char *ownerDisplayName,
                              int *aclGrantCountReturn,
                              S3AclGrant *aclGrants)
{
    *aclGrantCountReturn = 0;
    *ownerId = 0;
    *ownerDisplayName = 0;

#define SKIP_SPACE(require_more)                \
    do {                                        \
        while (isspace(*aclXml)) {              \
            aclXml++;                           \
        }                                       \
        if (require_more && !*aclXml) {         \
            return 0;                           \
        }                                       \
    } while (0)
    
#define COPY_STRING_MAXLEN(field, maxlen)               \
    do {                                                \
        SKIP_SPACE(1);                                  \
        int len = 0;                                    \
        while ((len < maxlen) && !isspace(*aclXml)) {   \
            field[len++] = *aclXml++;                   \
        }                                               \
        field[len] = 0;                                 \
    } while (0)

#define COPY_STRING(field)                              \
    COPY_STRING_MAXLEN(field, (int) (sizeof(field) - 1))

    while (1) {
        SKIP_SPACE(0);

        if (!*aclXml) {
            break;
        }
        
        // Skip Type lines and dash lines
        if (!strncmp(aclXml, "Type", sizeof("Type") - 1) ||
            (*aclXml == '-')) {
            while (*aclXml && ((*aclXml != '\n') && (*aclXml != '\r'))) {
                aclXml++;
            }
            continue;
        }
        
        if (!strncmp(aclXml, "OwnerID", sizeof("OwnerID") - 1)) {
            aclXml += sizeof("OwnerID") - 1;
            COPY_STRING_MAXLEN(ownerId, S3_MAX_GRANTEE_USER_ID_SIZE);
            SKIP_SPACE(1);
            COPY_STRING_MAXLEN(ownerDisplayName,
                               S3_MAX_GRANTEE_DISPLAY_NAME_SIZE);
            continue;
        }

        if (*aclGrantCountReturn == S3_MAX_ACL_GRANT_COUNT) {
            return 0;
        }

        S3AclGrant *grant = &(aclGrants[(*aclGrantCountReturn)++]);

        if (!strncmp(aclXml, "Email", sizeof("Email") - 1)) {
            grant->granteeType = S3GranteeTypeAmazonCustomerByEmail;
            aclXml += sizeof("Email") - 1;
            COPY_STRING(grant->grantee.amazonCustomerByEmail.emailAddress);
        }
        else if (!strncmp(aclXml, "UserID", sizeof("UserID") - 1)) {
            grant->granteeType = S3GranteeTypeCanonicalUser;
            aclXml += sizeof("UserID") - 1;
            COPY_STRING(grant->grantee.canonicalUser.id);
            SKIP_SPACE(1);
            // Now do display name
            COPY_STRING(grant->grantee.canonicalUser.displayName);
        }
        else if (!strncmp(aclXml, "Group", sizeof("Group") - 1)) {
            aclXml += sizeof("Group") - 1;
            SKIP_SPACE(1);
            if (!strncmp(aclXml, "Authenticated AWS Users",
                         sizeof("Authenticated AWS Users") - 1)) {
                grant->granteeType = S3GranteeTypeAllAwsUsers;
                aclXml += (sizeof("Authenticated AWS Users") - 1);
            }
            else if (!strncmp(aclXml, "All Users", sizeof("All Users") - 1)) {
                grant->granteeType = S3GranteeTypeAllUsers;
                aclXml += (sizeof("All Users") - 1);
            }
            else if (!strncmp(aclXml, "Log Delivery", 
                              sizeof("Log Delivery") - 1)) {
                grant->granteeType = S3GranteeTypeLogDelivery;
                aclXml += (sizeof("Log Delivery") - 1);
            }
            else {
                return 0;
            }
        }
        else {
            return 0;
        }

        SKIP_SPACE(1);
        
        if (!strncmp(aclXml, "READ_ACP", sizeof("READ_ACP") - 1)) {
            grant->permission = S3PermissionReadACP;
            aclXml += (sizeof("READ_ACP") - 1);
        }
        else if (!strncmp(aclXml, "READ", sizeof("READ") - 1)) {
            grant->permission = S3PermissionRead;
            aclXml += (sizeof("READ") - 1);
        }
        else if (!strncmp(aclXml, "WRITE_ACP", sizeof("WRITE_ACP") - 1)) {
            grant->permission = S3PermissionWriteACP;
            aclXml += (sizeof("WRITE_ACP") - 1);
        }
        else if (!strncmp(aclXml, "WRITE", sizeof("WRITE") - 1)) {
            grant->permission = S3PermissionWrite;
            aclXml += (sizeof("WRITE") - 1);
        }
        else if (!strncmp(aclXml, "FULL_CONTROL", 
                          sizeof("FULL_CONTROL") - 1)) {
            grant->permission = S3PermissionFullControl;
            aclXml += (sizeof("FULL_CONTROL") - 1);
        }
    }

    return 1;
}


static int should_retry()
{
    if (retriesG--) {
        // Sleep before next retry; start out with a 1 second sleep
        static int retrySleepInterval = 1;
        sleep(retrySleepInterval);
        // Next sleep 1 second longer
        retrySleepInterval++;
        return 1;
    }

    return 0;
}


static struct option longOptionsG[] =
{
    { "force",                no_argument,        0,  'f' },
    { "vhost-style",          no_argument,        0,  'h' },
    { "unencrypted",          no_argument,        0,  'u' },
    { "show-properties",      no_argument,        0,  's' },
    { "retries",              required_argument,  0,  'r' },
    { 0,                      0,                  0,   0  }
};



// response properties callback ----------------------------------------------

// This callback does the same thing for every request type: prints out the
// properties if the user has requested them to be so
static S3Status responsePropertiesCallback
    (const S3ResponseProperties *properties, void *callbackData)
{
    (void) callbackData;

    if (!showResponsePropertiesG) {
        return S3StatusOK;
    }

#define print_nonnull(name, field)                                 \
    do {                                                           \
        if (properties-> field) {                                  \
            printf("%s: %s\n", name, properties-> field);          \
        }                                                          \
    } while (0)
    
    print_nonnull("Content-Type", contentType);
    print_nonnull("Request-Id", requestId);
    print_nonnull("Request-Id-2", requestId2);
    if (properties->contentLength > 0) {
        printf("Content-Length: %lld\n", 
               (unsigned long long) properties->contentLength);
    }
    print_nonnull("Server", server);
    print_nonnull("ETag", eTag);
    if (properties->lastModified > 0) {
        char timebuf[256];
        time_t t = (time_t) properties->lastModified;
        // gmtime is not thread-safe but we don't care here.
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
        printf("Last-Modified: %s\n", timebuf);
    }
    int i;
    for (i = 0; i < properties->metaDataCount; i++) {
        printf("x-amz-meta-%s: %s\n", properties->metaData[i].name,
               properties->metaData[i].value);
    }

    return S3StatusOK;
}


// response complete callback ------------------------------------------------

// This callback does the same thing for every request type: saves the status
// and error stuff in global variables
static void responseCompleteCallback(S3Status status,
                                     const S3ErrorDetails *error, 
                                     void *callbackData)
{
    (void) callbackData;

    statusG = status;
    // Compose the error details message now, although we might not use it.
    // Can't just save a pointer to [error] since it's not guaranteed to last
    // beyond this callback
    int len = 0;
    if (error && error->message) {
        len += snprintf(&(errorDetailsG[len]), sizeof(errorDetailsG) - len,
                        "  Message: %s\n", error->message);
    }
    if (error && error->resource) {
        len += snprintf(&(errorDetailsG[len]), sizeof(errorDetailsG) - len,
                        "  Resource: %s\n", error->resource);
    }
    if (error && error->furtherDetails) {
        len += snprintf(&(errorDetailsG[len]), sizeof(errorDetailsG) - len,
                        "  Further Details: %s\n", error->furtherDetails);
    }
    if (error && error->extraDetailsCount) {
        len += snprintf(&(errorDetailsG[len]), sizeof(errorDetailsG) - len,
                        "%s", "  Extra Details:\n");
        int i;
        for (i = 0; i < error->extraDetailsCount; i++) {
            len += snprintf(&(errorDetailsG[len]), 
                            sizeof(errorDetailsG) - len, "    %s: %s\n", 
                            error->extraDetails[i].name,
                            error->extraDetails[i].value);
        }
    }
}


// put object ----------------------------------------------------------------

typedef struct put_object_callback_data
{
    FILE *infile;
    growbuffer *gb;
    uint64_t contentLength, originalContentLength;
    int noStatus;
} put_object_callback_data;


static int putObjectDataCallback(int bufferSize, char *buffer,
                                 void *callbackData)
{
    put_object_callback_data *data = 
        (put_object_callback_data *) callbackData;
    
    int ret = 0;

    if (data->contentLength) {
        int toRead = ((data->contentLength > (unsigned) bufferSize) ?
                      (unsigned) bufferSize : data->contentLength);
        if (data->gb) {
            growbuffer_read(&(data->gb), toRead, &ret, buffer);
        }
        else if (data->infile) {
            ret = fread(buffer, 1, toRead, data->infile);
        }
    }

    data->contentLength -= ret;

    if (data->contentLength && !data->noStatus) {
        // Avoid a weird bug in MingW, which won't print the second integer
        // value properly when it's in the same call, so print separately
        printf("%llu bytes remaining ", 
               (unsigned long long) data->contentLength);
        printf("(%d%% complete) ...\n",
               (int) (((data->originalContentLength - 
                        data->contentLength) * 100) /
                      data->originalContentLength));
    }

    return ret;
}


//static void put_object(int argc, char **argv, int optindex)
int put_object(const char* bucketName, const char* key, const char *filename)
{

    uint64_t contentLength = 0;
    const char *cacheControl = 0, *contentType = 0, *md5 = 0;
    const char *contentDispositionFilename = 0, *contentEncoding = 0;
    int64_t expires = -1;
    S3CannedAcl cannedAcl = S3CannedAclPrivate;
    int metaPropertiesCount = 0;
    S3NameValue metaProperties[S3_MAX_METADATA_COUNT];
    int noStatus = 0;

    put_object_callback_data data;

    data.infile = 0;
    data.gb = 0;
    data.noStatus = noStatus;
    
    
    if (!contentLength) {
            struct stat statbuf;
            // Stat the file to get its length
            if (stat(filename, &statbuf) == -1) {
	      fprintf(stderr, "\nERROR: Failed to stat file %s: ",
		      filename);
	      return 0; 
            }
            contentLength = statbuf.st_size;
    }
    // Open the file
    if (!(data.infile = fopen(filename, "r" FOPEN_EXTRA_FLAGS))) {
      fprintf(stderr, "\nERROR: Failed to open input file %s: ",
	      filename);
      return 0; 
      
    }
    
    data.contentLength = data.originalContentLength = contentLength;
    
    S3BucketContext bucketContext =
    {
        bucketName,
        protocolG,
        uriStyleG,
	AWS_ACCESS_KEY, 
	AWS_SECRET
    };

    S3PutProperties putProperties =
    {
        contentType,
        md5,
        cacheControl,
        contentDispositionFilename,
        contentEncoding,
        expires,
        cannedAcl,
        metaPropertiesCount,
        metaProperties
    };

    S3PutObjectHandler putObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &putObjectDataCallback
    };

    do {
        S3_put_object(&bucketContext, key, contentLength, &putProperties, 0,
                      &putObjectHandler, &data);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (data.infile) {
        fclose(data.infile);
    }
    else if (data.gb) {
        growbuffer_destroy(data.gb);
    }

    if (statusG != S3StatusOK) {
      return 0; 
    }
    
    return 1; 
}



// get object ----------------------------------------------------------------

static S3Status getObjectDataCallback(int bufferSize, const char *buffer,
                                      void *callbackData)
{
    FILE *outfile = (FILE *) callbackData;

    size_t wrote = fwrite(buffer, 1, bufferSize, outfile);
    
    return ((wrote < (size_t) bufferSize) ? 
            S3StatusAbortedByCallback : S3StatusOK);
}

// get_object ------------------------------------------------------------------

int get_object(const char* bucketName, const char* key, const char* filename)
{
  
  int64_t ifModifiedSince = -1, ifNotModifiedSince = -1;
  const char *ifMatch = 0, *ifNotMatch = 0;
  uint64_t startByte = 0, byteCount = 0;
  
  FILE *outfile = 0;
  
  if (filename) {
    // Stat the file, and if it doesn't exist, open it in w mode
    struct stat buf;
        if (stat(filename, &buf) == -1) {
            outfile = fopen(filename, "w" FOPEN_EXTRA_FLAGS);
        }
        else {
            // Open in r+ so that we don't truncate the file, just in case
            // there is an error and we write no bytes, we leave the file
            // unmodified
            outfile = fopen(filename, "r+" FOPEN_EXTRA_FLAGS);
        }
        
        if (!outfile) {
            fprintf(stderr, "\nERROR: Failed to open output file %s: ",
                    filename);
            perror(0);
            exit(-1);
        }
    }
    
    S3BucketContext bucketContext =
    {
        bucketName,
        protocolG,
        uriStyleG,
	AWS_ACCESS_KEY, 
	AWS_SECRET
    };

    S3GetConditions getConditions =
    {
        ifModifiedSince,
        ifNotModifiedSince,
        ifMatch,
        ifNotMatch
    };

    S3GetObjectHandler getObjectHandler =
    {
        { &responsePropertiesCallback, &responseCompleteCallback },
        &getObjectDataCallback
    };

    do {
        S3_get_object(&bucketContext, key, &getConditions, startByte,
                      byteCount, 0, &getObjectHandler, outfile);
    } while (S3_status_is_retryable(statusG) && should_retry());

    if (statusG != S3StatusOK) {
      return 0; 
    }

    fclose(outfile);
    return 1; 

}
