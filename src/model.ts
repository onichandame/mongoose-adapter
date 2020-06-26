import { prop, modelOptions } from '@typegoose/typegoose';

@modelOptions({
  schemaOptions: {
    collection: 'casbin_rule',
    minimize: false,
    timestamps: false,
  },
})
export class CasbinRule {
  @prop({ required: true, index: true })
  public p_type!: string;
  @prop({ index: true })
  public v0?: string;
  @prop({ index: true })
  public v1?: string;
  @prop({ index: true })
  public v2?: string;
  @prop({ index: true })
  public v3?: string;
  @prop({ index: true })
  public v4?: string;
  @prop({ index: true })
  public v5?: string;
}
