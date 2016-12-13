### Wechat middleware for koa 2

### install

```bash
npm install --save @alphatr/koa-wechat
```
### how to use

```javascript
app.use(wechat('token').middleware((ctx, next) => {
    const message = ctx.state.wechat;
    // do something

    ctx.body = 'response';
    return next();
});
```
