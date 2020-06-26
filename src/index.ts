import { Helper, FilteredAdapter, Filter, Model } from "casbin"
import { Connection, connection as defConnection } from "mongoose"
import { getModelForClass } from "@typegoose/typegoose"
import debug from "debug"

import { CasbinRule } from "./model"

const defLogger = debug("MongooseAdapter")

/*
 * This class does not create mongoose connection. You need to create a connection then pass it to the constructor of this class.
 * If connection not passed, the default mongoose connection will be used
 */
export class MongooseAdapter implements FilteredAdapter {
  private connection: Connection
  private logger: ReturnType<typeof debug>
  private _isFiltered: boolean = false
  constructor({
    connection = defConnection,
    logger = defLogger
  }: {
    connection?: Connection
    logger?: ReturnType<typeof debug>
  } = {}) {
    this.connection = connection
    this.logger = logger
  }
  private async loadPolicyLine(line: CasbinRule, model: Model) {
    const lineText = [
      line.p_type,
      ...Object.keys([...Array(6)])
        .map(index =>
          `v${index}` in line ? line[`v${index}` as keyof CasbinRule] : null
        )
        .filter(v => !!v)
    ].join(", ")
    Helper.loadPolicyLine(lineText, model)
  }
  private savePolicyLine(ptype: string, rule: string[]) {
    const model: CasbinRule = { p_type: ptype }
    rule.forEach((str, index) => {
      const key: keyof CasbinRule = `v${index}` as keyof CasbinRule
      model[key] = str
    })
    return model
  }
  private get RuleModel() {
    return getModelForClass(CasbinRule, {
      existingConnection: this.connection
    })
  }
  public isFiltered() {
    return this._isFiltered
  }
  public async loadFilteredPolicy(model: Model, filter?: Filter) {
    if (filter) this._isFiltered = true
    else this._isFiltered = false
    const lines = await this.RuleModel.find(filter || {})
    for (const line of lines) this.loadPolicyLine(line, model)
  }
  public async loadPolicy(model: Model) {
    return this.loadFilteredPolicy(model)
  }
  public async savePolicy(model: Model) {
    try {
      const lines: CasbinRule[] = []
      const policyRuleAST = model.model.get("p")
      const groupingPolicyAST = model.model.get("g")
      if (policyRuleAST)
        for (const [ptype, ast] of policyRuleAST)
          for (const rule of ast.policy)
            lines.push(new this.RuleModel(this.savePolicyLine(ptype, rule)))

      if (groupingPolicyAST)
        for (const [ptype, ast] of groupingPolicyAST)
          for (const rule of ast.policy)
            lines.push(this.savePolicyLine(ptype, rule))
      await this.RuleModel.collection.insertMany(lines)
      return true
    } catch (e) {
      this.logger(
        `failed to save policy ${JSON.stringify(
          model.model
        )} due to ${JSON.stringify(e.message || e)}`
      )
      return false
    }
  }
  public async addPolicy(_: string, ptype: string, rule: string[]) {
    try {
      const line = new this.RuleModel(this.savePolicyLine(ptype, rule))
      await line.save()
    } catch (e) {
      this.logger(
        `failed to add policy ${ptype}, ${rule.join(
          ", "
        )} due to ${JSON.stringify(e.message || e)}`
      )
      throw e
    }
  }
  public async addPolicies(sec: string, ptype: string, rules: string[][]) {
    try {
      const p: Promise<any>[] = rules.map(rule =>
        this.addPolicy(sec, ptype, rule)
      )
      await Promise.all(p)
    } catch (e) {
      this.logger(
        `failed to add policies ${ptype}, ${JSON.stringify(
          rules
        )} due to ${JSON.stringify(e.message || e)}`
      )
      throw e
    }
  }
  public async removePolicy(_: string, ptype: string, rule: string[]) {
    try {
      const model = this.savePolicyLine(ptype, rule)
      const { ok } = await this.RuleModel.deleteMany(model)
      if (!ok)
        throw new Error(
          `failed to delete policies with filter ${JSON.stringify(model)}`
        )
    } catch (e) {
      this.logger(
        `failed to remove policy ${ptype}, ${rule.join(
          ", "
        )} due to ${JSON.stringify(e.message || e)}`
      )
      throw e
    }
  }
  public async removePolicies(sec: string, ptype: string, rules: string[][]) {
    return Promise.all(rules.map(rule => this.removePolicy(sec, ptype, rule)))
  }
  public async removeFilteredPolicy(
    _: string,
    ptype: string,
    fieldIndex: number,
    ...fieldValues: string[]
  ) {
    try {
      const model = new this.RuleModel({ p_type: ptype })
      const filters = [
        ...Array(fieldIndex).map(() => null),
        ...fieldValues
      ].splice(0, 6)
      filters.forEach((filter, index) => {
        if (filter !== null) {
          const key: keyof CasbinRule = `v${index}` as keyof CasbinRule
          model[key] = filter
        }
      })
      await this.RuleModel.deleteMany(model)
    } catch (e) {
      this.logger(
        `failed to remove policies with filter ${ptype}, ${fieldValues.join(
          ", "
        )} with filter`
      )
      throw e
    }
  }
  public async clearPolicy() {
    this.logger(`deleting all policies!`)
    return this.RuleModel.deleteMany({})
  }
}
