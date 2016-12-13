const getRawBody = require('raw-body');
const xml2js = require('xml2js');
const crypto = require('crypto');
const ejs = require('ejs');
const WXBizMsgCrypt = require('wechat-crypto');

const Wechat = function Wechat(config) {
    if (!(this instanceof Wechat)) {
        return new Wechat(config);
    }
    return this.setToken(config);
};

Wechat.prototype.setToken = function setToken(config) {
    if (typeof config === 'string') {
        this.token = config;
    } else if (typeof config === 'object' && config.token) {
        this.token = config.token;
        this.appid = config.appid || '';
        this.encodingAESKey = config.encodingAESKey || '';
    } else {
        throw new TypeError('please check your config');
    }
};

const getSignature = function getSignature(timestamp, nonce, token) {
    const shasum = crypto.createHash('sha1');
    const arr = [token, timestamp, nonce].sort();
    shasum.update(arr.join(''));

    return shasum.digest('hex');
};

const parseXML = function parseXML(xml) {
    return new Promise((resolve, reject) => {
        xml2js.parseString(xml, {trim: true}, (err, data) => {
            if (err) {
                return reject(err);
            }

            return resolve(data);
        });
    });
};

/*!
 * 将xml2js解析出来的对象转换成直接可访问的对象
 */
const formatMessage = function formatMessage(result) {
    const message = {};
    if (typeof result === 'object') {
        for (const key in result) {
            if (!(result[key] instanceof Array) || result[key].length === 0) {
                continue;
            }

            if (result[key].length === 1) {
                const val = result[key][0];
                if (typeof val === 'object') {
                    message[key] = formatMessage(val);
                } else {
                    message[key] = (val || '').trim();
                }
            } else {
                message[key] = result[key].map(item => formatMessage(item));
            }
        }
    }
    return message;
};

/*!
 * 响应模版
 */
const tpl = `<xml>
    <ToUserName><![CDATA[<%-toUsername%>]]></ToUserName>
    <FromUserName><![CDATA[<%-fromUsername%>]]></FromUserName>
    <CreateTime><%=createTime%></CreateTime>
    <MsgType><![CDATA[<%=msgType%>]]></MsgType>
    <% if (msgType === "news") { %>
        <ArticleCount><%=content.length%></ArticleCount>
        <Articles>
        <% content.forEach(function(item){ %>
            <item>
                <Title><![CDATA[<%-item.title%>]]></Title>
                <Description><![CDATA[<%-item.description%>]]></Description>
                <PicUrl><![CDATA[<%-item.picUrl || item.picurl || item.pic || item.thumb_url %>]]></PicUrl>
                <Url><![CDATA[<%-item.url%>]]></Url>
            </item>
        <% }); %>
        </Articles>
    <% } else if (msgType === "music") { %>
        <Music>
            <Title><![CDATA[<%-content.title%>]]></Title>
            <Description><![CDATA[<%-content.description%>]]></Description>
            <MusicUrl><![CDATA[<%-content.musicUrl || content.url %>]]></MusicUrl>
            <HQMusicUrl><![CDATA[<%-content.hqMusicUrl || content.hqUrl %>]]></HQMusicUrl>
        </Music>
    <% } else if (msgType === "voice") { %>
        <Voice>
            <MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>
        </Voice>
    <% } else if (msgType === "image") { %>
        <Image>
            <MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>
        </Image>
    <% } else if (msgType === "video") { %>
        <Video>
            <MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>
            <Title><![CDATA[<%-content.title%>]]></Title>
            <Description><![CDATA[<%-content.description%>]]></Description>
        </Video>
    <% } else if (msgType === "transfer_customer_service") { %>
        <% if (content && content.kfAccount) { %>
            <TransInfo>
                <KfAccount><![CDATA[<%-content.kfAccount%>]]></KfAccount>
            </TransInfo>
        <% } %>
    <% } else { %>
        <Content><![CDATA[<%-content%>]]></Content>
    <% } %>
</xml>`;

/*!
 * 编译过后的模版
 */
const compiled = ejs.compile(tpl);

const wrapTpl = `<xml>
    <Encrypt><![CDATA[<%-encrypt%>]]></Encrypt>
    <MsgSignature><![CDATA[<%-signature%>]]></MsgSignature>
    <TimeStamp><%-timestamp%></TimeStamp>
    <Nonce><![CDATA[<%-nonce%>]]></Nonce>
</xml>`;

const encryptWrap = ejs.compile(wrapTpl);

const reply2CustomerService = function reply2CustomerService(fromUsername, toUsername, kfAccount) {
    const info = {};
    info.msgType = 'transfer_customer_service';
    info.createTime = new Date().getTime();
    info.toUsername = toUsername;
    info.fromUsername = fromUsername;
    info.content = {};
    if (typeof kfAccount === 'string') {
        info.content.kfAccount = kfAccount;
    }
    return compiled(info);
};

/*!
 * 将内容回复给微信的封装方法
 */
const reply = function reply(content, fromUsername, toUsername) {
    const info = {};
    let type = 'text';
    info.content = content || '';
    if (Array.isArray(content)) {
        type = 'news';
    } else if (typeof content === 'object') {
        if (content.type) {
            if (content.type === 'customerService') {
                return reply2CustomerService(fromUsername, toUsername, content.kfAccount);
            }
            type = content.type;
            info.content = content.content;
        } else {
            type = 'music';
        }
    }

    info.msgType = type;
    info.createTime = new Date().getTime();
    info.toUsername = toUsername;
    info.fromUsername = fromUsername;
    return compiled(info);
};

Wechat.prototype._session = function _session(handle, sessionId, ctx) {
    // 取session数据
    this.wxSessionId = sessionId;
    const _this = this;
    return this.sessionStore.get(this.wxSessionId).then(session => {
        _this.wxsession = session;

        if (!session) {
            _this.wxsession = {};
            _this.wxsession.cookie = _this.session.cookie;
        }

        // 业务逻辑处理
        return Reflect.apply(handle, this, [ctx]);
    }).then(() => {
        // 更新 session
        if (_this.wxsession) {
            return _this.sessionStore.set(_this.wxSessionId, _this.wxsession);
        }

        if (_this.wxSessionId) {
            return _this.sessionStore.destroy(_this.wxSessionId);
        }

        return null;
    });
};

Wechat.prototype.middleware = function middleware(handle) {
    const _this = this;
    if (this.encodingAESKey) {
        this.cryptor = new WXBizMsgCrypt(this.token, this.encodingAESKey, this.appid);
    }

    return (ctx, next) => {
        const query = ctx.query;
        let method = ctx.method.toLowerCase();

        const timestamp = query.timestamp;
        const nonce = query.nonce;
        const echostr = query.echostr;

        // 加密模式
        if (query.encrypt_type && query.encrypt_type === 'aes' && query.msg_signature) {
            const encrypt = 'aes';
            method = encrypt + method.replace(/^./ig, first => first.toUpperCase());
        }

        const methodHandles = {
            get() {
                if (query.signature !== getSignature(timestamp, nonce, _this.token)) {
                    return methodHandles._errorSign();
                }

                ctx.body = echostr;
                return null;
            },

            aesGet() {
                if (query.msg_signature !== _this.cryptor.getSignature(timestamp, nonce, echostr)) {
                    return methodHandles._errorSign();
                }

                const decrypted = _this.cryptor.decrypt(echostr);
                ctx.body = decrypted.message;
                return null;
            },

            post() {
                // 校验
                if (query.signature !== getSignature(timestamp, nonce, _this.token)) {
                    return methodHandles._errorSign();
                }

                // 取原始数据
                return getRawBody(ctx.req, {
                    length: ctx.length,
                    limit: '1mb',
                    encoding: ctx.charset
                }).then(xml => {
                    // 解析xml
                    ctx.state.wechatXml = xml;
                    return parseXML(xml);
                }).then(parsed => {
                    const formated = formatMessage(parsed.xml);

                    // 挂载处理后的微信消息
                    ctx.state.wechat = formated;

                    if (this.sessionStore) {
                        return this._session(handle, formated.FromUserName, ctx);
                    }

                    return Reflect.apply(handle, this, [ctx, next]);
                }).then(() => {
                    const formated = ctx.state.wechat;
                    if (ctx.body !== '') {
                        ctx.body = reply(ctx.body, formated.ToUserName, formated.FromUserName);
                        ctx.type = 'application/xml';
                    }
                });
            },

            aesPost() {
                // 取原始数据
                return getRawBody(ctx.req, {
                    length: ctx.length,
                    limit: '1mb',
                    encoding: ctx.charset
                }).then(xml => {
                    // 解析xml
                    ctx.state.wechatXml = xml;
                    return parseXML(xml);
                }).then(parsed => {
                    // 解析xml
                    const formated = formatMessage(parsed.xml);

                    const encryptMessage = formated.Encrypt;
                    if (query.msg_signature !== _this.cryptor.getSignature(timestamp, nonce, encryptMessage)) {
                        return this._errorSign();
                    }

                    const decryptedXML = _this.cryptor.decrypt(encryptMessage);
                    const messageWrapXml = decryptedXML.message;

                    if (!messageWrapXml) {
                        return this._errorSign();
                    }

                    return parseXML(messageWrapXml).then(decodedXML => {
                        ctx.state.wechat = formatMessage(decodedXML.xml);

                        if (this.sessionStore) {
                            return this._session(handle, formated.FromUserName, ctx);
                        }

                        return Reflect.apply(handle, this, [ctx, next]);
                    }).then(() => {
                        const formatedData = ctx.state.wechat;
                        if (ctx.body !== '') {
                            const replyMessageXml = reply(ctx.body, formatedData.ToUserName, formatedData.FromUserName);
                            const wrap = {};

                            wrap.encrypt = _this.cryptor.encrypt(replyMessageXml);
                            wrap.nonce = parseInt(Math.random() * 100000000000, 10);
                            wrap.timestamp = new Date().getTime();
                            wrap.signature = _this.cryptor.getSignature(wrap.timestamp, wrap.nonce, wrap.encrypt);
                            ctx.body = encryptWrap(wrap);
                            this.type = 'application/xml';
                        }
                    });
                });
            },

            _errorSign() {
                this.status = 401;
                this.body = 'Invalid signature';
            },

            _call() {
                ctx.status = 501;
                ctx.body = 'Not Implemented';
            }
        };

        if (methodHandles[method]) {
            return methodHandles[method]();
        }

        return methodHandles._call();
    };
};

module.exports = Wechat;
