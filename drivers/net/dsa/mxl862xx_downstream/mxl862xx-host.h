int mxl862xx_write(struct mxl862xx_priv *dev, u32 regaddr, u16 data);
extern int mxl862xx_api_wrap(struct mxl862xx_priv *priv, u16 cmd, void *data, u16 size, bool read);

int mxl862xx_smdio_read(struct mxl862xx_priv *priv, u32 addr);
int mxl862xx_smdio_write(struct mxl862xx_priv *priv, u32 addr, u16 val);

