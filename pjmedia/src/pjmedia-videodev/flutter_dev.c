/* $Id$ */
/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <pjmedia-videodev/videodev_imp.h>
#include <pjmedia/event.h>
#include <pj/assert.h>
#include <pj/log.h>
#include <pj/os.h>

#define THIS_FILE "flutter_dev.c"

#define DEFAULT_CLOCK_RATE 90000
#define DEFAULT_WIDTH 640
#define DEFAULT_HEIGHT 480
#define DEFAULT_FPS 25

typedef struct flutter_fmt_info
{
    pjmedia_format_id fmt_id;
    int flutter_format;
} flutter_fmt_info;

static flutter_fmt_info flutter_fmts[] =
    {
        {PJMEDIA_FORMAT_RGBA, 0},
};

struct flutter_dev_info
{
    pjmedia_vid_dev_info info;
};

/* Linked list of streams */
struct stream_list
{
    PJ_DECL_LIST_MEMBER(struct stream_list);
    struct flutter_stream *stream;
};

struct flutter_factory
{
    pjmedia_vid_dev_factory base;
    pj_pool_t *pool;
    pj_pool_factory *pf;

    unsigned dev_count;
    struct flutter_dev_info *dev_info;
    struct stream_list streams;

    pj_sem_t *sem;
    pj_mutex_t *mutex;
};

/* Video stream. */
struct flutter_stream
{
    pjmedia_vid_dev_stream base; /**< Base stream	    */
    pjmedia_vid_dev_param param; /**< Settings	    */
    pj_pool_t *pool;             /**< Memory pool.       */

    pjmedia_vid_dev_cb vid_cb; /**< Stream callback.   */
    void *user_data;           /**< Application data.  */

    struct flutter_factory *ff;
    const pjmedia_frame *frame;
    pj_bool_t is_running;
    pj_timestamp last_ts;
    struct stream_list list_entry;

    pjmedia_video_apply_fmt_param vafp;
    flutter_fmt_info *cf;
    void *frame_buf;
};

/* Prototypes */
static pj_status_t flutter_factory_init(pjmedia_vid_dev_factory *f);
static pj_status_t flutter_factory_destroy(pjmedia_vid_dev_factory *f);
static pj_status_t flutter_factory_refresh(pjmedia_vid_dev_factory *f);
static unsigned flutter_factory_get_dev_count(pjmedia_vid_dev_factory *f);
static pj_status_t flutter_factory_get_dev_info(pjmedia_vid_dev_factory *f,
                                                unsigned index,
                                                pjmedia_vid_dev_info *info);
static pj_status_t flutter_factory_default_param(pj_pool_t *pool,
                                                 pjmedia_vid_dev_factory *f,
                                                 unsigned index,
                                                 pjmedia_vid_dev_param *param);
static pj_status_t flutter_factory_create_stream(
    pjmedia_vid_dev_factory *f,
    pjmedia_vid_dev_param *param,
    const pjmedia_vid_dev_cb *cb,
    void *user_data,
    pjmedia_vid_dev_stream **p_vid_strm);

static pj_status_t flutter_stream_get_param(pjmedia_vid_dev_stream *strm,
                                            pjmedia_vid_dev_param *param);
static pj_status_t flutter_stream_get_cap(pjmedia_vid_dev_stream *strm,
                                          pjmedia_vid_dev_cap cap,
                                          void *value);
static pj_status_t flutter_stream_set_cap(pjmedia_vid_dev_stream *strm,
                                          pjmedia_vid_dev_cap cap,
                                          const void *value);
static pj_status_t flutter_stream_put_frame(pjmedia_vid_dev_stream *strm,
                                            const pjmedia_frame *frame);
static pj_status_t flutter_stream_start(pjmedia_vid_dev_stream *strm);
static pj_status_t flutter_stream_stop(pjmedia_vid_dev_stream *strm);
static pj_status_t flutter_stream_destroy(pjmedia_vid_dev_stream *strm);

/* Operations */
static pjmedia_vid_dev_factory_op factory_op =
    {
        &flutter_factory_init,
        &flutter_factory_destroy,
        &flutter_factory_get_dev_count,
        &flutter_factory_get_dev_info,
        &flutter_factory_default_param,
        &flutter_factory_create_stream,
        &flutter_factory_refresh};

static pjmedia_vid_dev_stream_op stream_op =
    {
        &flutter_stream_get_param,
        &flutter_stream_get_cap,
        &flutter_stream_set_cap,
        &flutter_stream_start,
        NULL,
        &flutter_stream_put_frame,
        &flutter_stream_stop,
        &flutter_stream_destroy};

/*
 * Util
 */
static void flutter_log_err(const char *op, const char *msg)
{
    PJ_LOG(1, (THIS_FILE, "%s error: %s", op, msg));
}

static flutter_fmt_info *get_flutter_format_info(pjmedia_format_id id)
{
    unsigned i;

    for (i = 0; i < sizeof(flutter_fmts) / sizeof(flutter_fmts[0]); i++)
    {
        if (flutter_fmts[i].fmt_id == id)
            return &flutter_fmts[i];
    }

    return NULL;
}

static pj_status_t flutter_create_rend(struct flutter_stream *strm,
                                       pjmedia_format *fmt)
{

    const pjmedia_video_format_info *vfi;
    flutter_fmt_info *flutter_info;

    flutter_info = get_flutter_format_info(fmt->id);

    vfi = pjmedia_get_video_format_info(pjmedia_video_format_mgr_instance(),
                                        fmt->id);

    if (!vfi || !flutter_info)
    {
        return PJMEDIA_EVID_BADFORMAT;
    }

    strm->cf = flutter_info;
    strm->vafp.size = fmt->det.vid.size;
    strm->vafp.buffer = NULL;
    if (vfi->apply_fmt(vfi, &strm->vafp) != PJ_SUCCESS)
    {
        return PJMEDIA_EVID_BADFORMAT;
    }
    return PJ_SUCCESS;
    // strm->frame_buf = pj_pool_alloc(strm->pool, strm->vafp.framebytes);
}

/****************************************************************************
 * Factory operations
 */
/*
 * Init flutter video driver.
 */
pjmedia_vid_dev_factory *pjmedia_flutter_factory(pj_pool_factory *pf)
{
    struct flutter_factory *f;
    pj_pool_t *pool;

    pool = pj_pool_create(pf, "flutter_video", 1000, 1000, NULL);
    f = PJ_POOL_ZALLOC_T(pool, struct flutter_factory);
    f->pf = pf;
    f->pool = pool;
    f->base.op = &factory_op;

    return &f->base;
}

static pj_status_t flutter_init(void *data)
{
    PJ_UNUSED_ARG(data);

    return PJ_SUCCESS;
}

/* API: init factory */
static pj_status_t flutter_factory_init(pjmedia_vid_dev_factory *f)
{
    struct flutter_factory *ff = (struct flutter_factory *)f;
    struct flutter_dev_info *ddi;
    unsigned i, j;
    pj_status_t status;
    pj_list_init(&ff->streams);

    status = pj_mutex_create_recursive(ff->pool, "flutter_factory",
                                       &ff->mutex);
    if (status != PJ_SUCCESS)
        return status;

    status = pj_sem_create(ff->pool, NULL, 0, 1, &ff->sem);
    if (status != PJ_SUCCESS)
        return status;

    ff->dev_count = 1;
    ff->dev_info = (struct flutter_dev_info *)
        pj_pool_calloc(ff->pool, ff->dev_count,
                       sizeof(struct flutter_dev_info));

    ddi = &ff->dev_info[0];
    pj_bzero(ddi, sizeof(*ddi));
    strncpy(ddi->info.name, "Flutter renderer", sizeof(ddi->info.name));
    ddi->info.name[sizeof(ddi->info.name) - 1] = '\0';
    ddi->info.fmt_cnt = PJ_ARRAY_SIZE(flutter_fmts);

    for (i = 0; i < ff->dev_count; i++)
    {
        ddi = &ff->dev_info[i];
        strncpy(ddi->info.driver, "Flutter", sizeof(ddi->info.driver));
        ddi->info.driver[sizeof(ddi->info.driver) - 1] = '\0';
        ddi->info.dir = PJMEDIA_DIR_RENDER;
        ddi->info.has_callback = PJ_FALSE;
        ddi->info.caps = PJMEDIA_VID_DEV_CAP_FORMAT | PJMEDIA_VID_DEV_CAP_FLUTTER_TEXTURE;

        for (j = 0; j < ddi->info.fmt_cnt; j++)
        {
            pjmedia_format *fmt = &ddi->info.fmt[j];
            pjmedia_format_init_video(fmt, flutter_fmts[j].fmt_id,
                                      DEFAULT_WIDTH, DEFAULT_HEIGHT,
                                      DEFAULT_FPS, 1);
        }
    }

    PJ_LOG(4, (THIS_FILE, "Flutter video driver initialized"));

    return PJ_SUCCESS;
}

/* API: destroy factory */
static pj_status_t flutter_factory_destroy(pjmedia_vid_dev_factory *f)
{
    struct flutter_factory *ff = (struct flutter_factory *)f;
    pj_pool_t *pool = ff->pool;
    pj_status_t status;

    if (ff->mutex)
    {
        pj_mutex_destroy(ff->mutex);
        ff->mutex = NULL;
    }

    if (ff->sem)
    {
        pj_sem_destroy(ff->sem);
        ff->sem = NULL;
    }

    ff->pool = NULL;
    pj_pool_release(pool);

    return PJ_SUCCESS;
}

/* API: refresh the list of devices */
static pj_status_t flutter_factory_refresh(pjmedia_vid_dev_factory *f)
{
    PJ_UNUSED_ARG(f);
    return PJ_SUCCESS;
}

/* API: get number of devices */
static unsigned flutter_factory_get_dev_count(pjmedia_vid_dev_factory *f)
{
    struct flutter_factory *ff = (struct flutter_factory *)f;
    return ff->dev_count;
}

static pj_status_t change_format(struct flutter_stream *strm,
                                 pjmedia_format *new_fmt)
{
    pj_status_t status;

    /* Reconfigure flutter renderer */
    status = flutter_create_rend(strm, (new_fmt ? new_fmt : &strm->param.fmt));
    if (status == PJ_SUCCESS && new_fmt)
        pjmedia_format_copy(&strm->param.fmt, new_fmt);

    return status;
}

/* API: get device info */
static pj_status_t flutter_factory_get_dev_info(pjmedia_vid_dev_factory *f,
                                                unsigned index,
                                                pjmedia_vid_dev_info *info)
{
    struct flutter_factory *ff = (struct flutter_factory *)f;

    PJ_ASSERT_RETURN(index < ff->dev_count, PJMEDIA_EVID_INVDEV);

    pj_memcpy(info, &ff->dev_info[index].info, sizeof(*info));

    return PJ_SUCCESS;
}

/* API: create default device parameter */
static pj_status_t flutter_factory_default_param(pj_pool_t *pool,
                                                 pjmedia_vid_dev_factory *f,
                                                 unsigned index,
                                                 pjmedia_vid_dev_param *param)
{

    struct flutter_factory *ff = (struct flutter_factory *)f;
    struct flutter_dev_info *di = &ff->dev_info[index];

    PJ_ASSERT_RETURN(index < ff->dev_count, PJMEDIA_EVID_INVDEV);

    PJ_UNUSED_ARG(pool);

    pj_bzero(param, sizeof(*param));
    param->dir = PJMEDIA_DIR_RENDER;
    param->rend_id = index;
    param->cap_id = PJMEDIA_VID_INVALID_DEV;

    /* Set the device capabilities here */
    param->flags = PJMEDIA_VID_DEV_CAP_FORMAT;
    param->fmt.type = PJMEDIA_TYPE_VIDEO;
    param->clock_rate = DEFAULT_CLOCK_RATE;

    pj_memcpy(&param->fmt, &di->info.fmt[0], sizeof(param->fmt));

    return PJ_SUCCESS;
}

static void put_frame(void *buffer, int w, int h, int size)
{
#if defined(PJ_DARWINOS) && PJ_DARWINOS != 0
    CVPixelBufferRef darwinBuffer = NULL;
    CVReturn result = CVPixelBufferCreate(
        kCFAllocatorDefault, w, h,
        format->flutter_format, (__bridge CFDictionaryRef) @{
            (__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey : [NSDictionary dictionary],
            (__bridge NSString *)kCVPixelBufferMetalCompatibilityKey : @YES
        },
        &darwinBuffer);

    if (result != kCVReturnSuccess)
    {
        PJ_LOG(2, (THIS_FILE, "Creation of empty BGRA buffer failed: %d", result));
    }

    CVPixelBufferLockBaseAddress(darwinBuffer, 0);
    uint8_t *baseAddress = CVPixelBufferGetBaseAddress(darwinBuffer);
    memcpy(baseAddress, buffer, size);
    CVPixelBufferUnlockBaseAddress(darwinBuffer, 0);

    if (call_id != -1)
    {
        [[textures getCallIdVideoTexture:@(call_id)] newFrameAvailable:darwinBuffer];
    }
    else
    {
        [[textures callerTexture] newFrameAvailable:darwinBuffer];
    }
#else  /* PJ_DARWINOS */
#endif /* PJ_DARWINOS */
}

/* API: Put frame from stream */
static pj_status_t flutter_stream_put_frame(pjmedia_vid_dev_stream *strm,
                                            const pjmedia_frame *frame)
{
    struct flutter_stream *stream = (struct flutter_stream *)strm;
    pj_status_t status;
    pjmedia_vid_dev_param vid_param;
    const pjmedia_video_format_detail *vfd_cur;

    stream->last_ts.u64 = frame->timestamp.u64;

    /* Video conference just trying to send heart beat for updating timestamp
     * or keep-alive, this port doesn't need any, just ignore.
     */
    if (frame->size == 0 || frame->buf == NULL)
        return PJ_SUCCESS;

    if (!stream->is_running)
        return PJ_EINVALIDOP;

    stream->frame = frame;

    int w = stream->vafp.size.w;
    int h = stream->vafp.size.h;

    /* Get current format, create platform buffer & send frame to flutter texture */

    if (stream->param.texture_id > 0)
    {
        int size = 0;
        if (stream->cf->fmt_id == PJMEDIA_FORMAT_RGBA)
        {
            size = h * stream->vafp.strides[0];
        }
        if (size > 0)
        {
            pjmedia_vid_dev_stream_get_param(strm, &vid_param);
            vfd_cur = pjmedia_format_get_video_format_detail(
                &vid_param.fmt, PJ_TRUE);
            if (!vfd_cur)
                return PJMEDIA_EVID_BADFORMAT;

            // (*pjsua_var.ua_cfg.cb.on_new_frame)(frame->buf, w, h, size, stream->param.texture_id);
            return PJ_SUCCESS;
        }
        else
        {
            PJ_LOG(1, (THIS_FILE, "txtdbgr Could not get frame size in bytes"));
        }
    }
    else
    {
        PJ_LOG(1, (THIS_FILE, "txtdbgr texture_id was not set"));
    }

    return PJ_EINVAL;
}

/* API: create stream */
static pj_status_t flutter_factory_create_stream(
    pjmedia_vid_dev_factory *f,
    pjmedia_vid_dev_param *param,
    const pjmedia_vid_dev_cb *cb,
    void *user_data,
    pjmedia_vid_dev_stream **p_vid_strm)
{
    PJ_LOG(1, (THIS_FILE, "Starting flutter stream"));
    struct flutter_factory *ff = (struct flutter_factory *)f;
    pj_pool_t *pool;
    struct flutter_stream *strm;

    PJ_ASSERT_RETURN(param->dir == PJMEDIA_DIR_RENDER, PJ_EINVAL);

    /* Create and Initialize stream descriptor */
    pool = pj_pool_create(ff->pf, "flutter-dev", 10000, 10000, NULL);
    PJ_ASSERT_RETURN(pool != NULL, PJ_ENOMEM);

    strm = PJ_POOL_ZALLOC_T(pool, struct flutter_stream);
    pj_memcpy(&strm->param, param, sizeof(*param));
    strm->pool = pool;
    strm->ff = ff;
    strm->param.texture_id = 0;
    pj_memcpy(&strm->vid_cb, cb, sizeof(*cb));
    pj_list_init(&strm->list_entry);
    strm->list_entry.stream = strm;
    strm->user_data = user_data;

    flutter_create_rend(strm, &strm->param.fmt);

    pj_mutex_lock(strm->ff->mutex);
    if (pj_list_empty(&strm->ff->streams))
        pj_sem_post(strm->ff->sem);
    pj_list_insert_after(&strm->ff->streams, &strm->list_entry);
    pj_mutex_unlock(strm->ff->mutex);

    /* Done */
    strm->base.op = &stream_op;
    *p_vid_strm = &strm->base;

    PJ_LOG(1, (THIS_FILE, "Flutter stream created"));

    return PJ_SUCCESS;
}

/* API: Get stream info. */
static pj_status_t flutter_stream_get_param(pjmedia_vid_dev_stream *s,
                                            pjmedia_vid_dev_param *pi)
{
    struct flutter_stream *strm = (struct flutter_stream *)s;

    PJ_ASSERT_RETURN(strm && pi, PJ_EINVAL);

    pj_memcpy(pi, &strm->param, sizeof(*pi));

    return PJ_SUCCESS;
}

/* API: get capability */
static pj_status_t flutter_stream_get_cap(pjmedia_vid_dev_stream *s,
                                          pjmedia_vid_dev_cap cap,
                                          void *pval)
{

    return PJ_SUCCESS;
}

/* API: set capability */
static pj_status_t flutter_stream_set_cap(pjmedia_vid_dev_stream *s,
                                          pjmedia_vid_dev_cap cap,
                                          const void *pval)
{
    struct flutter_stream *stream = (struct flutter_stream *)s;
    pj_status_t status = PJ_SUCCESS;

    if (cap == PJMEDIA_VID_DEV_CAP_FLUTTER_TEXTURE)
    {

        stream->param.texture_id = *((pj_uint64_t *)pval);
    }
    else if (cap == PJMEDIA_VID_DEV_CAP_FORMAT)
    {

        status = change_format(stream, (pjmedia_format *)pval);
    }

    return status;
}

/* API: Start stream. */
static pj_status_t flutter_stream_start(pjmedia_vid_dev_stream *strm)
{
    struct flutter_stream *stream = (struct flutter_stream *)strm;

    stream->is_running = PJ_TRUE;

    return PJ_SUCCESS;
}

/* API: Stop stream. */
static pj_status_t flutter_stream_stop(pjmedia_vid_dev_stream *strm)
{
    struct flutter_stream *stream = (struct flutter_stream *)strm;

    stream->is_running = PJ_FALSE;

    return PJ_SUCCESS;
}

/* API: Destroy stream. */
static pj_status_t flutter_stream_destroy(pjmedia_vid_dev_stream *strm)
{
    struct flutter_stream *stream = (struct flutter_stream *)strm;
    pj_status_t status;

    PJ_ASSERT_RETURN(stream != NULL, PJ_EINVAL);

    flutter_stream_stop(strm);

    pj_mutex_lock(stream->ff->mutex);
    if (!pj_list_empty(&stream->list_entry))
        pj_list_erase(&stream->list_entry);
    pj_mutex_unlock(stream->ff->mutex);

    pj_pool_release(stream->pool);

    return PJ_SUCCESS;
}