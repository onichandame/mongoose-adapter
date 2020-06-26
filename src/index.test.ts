import { connect, disconnect } from "mongoose"
import { getModelForClass } from "@typegoose/typegoose"
import { newEnforcer } from "casbin"
import { resolve } from "path"

import { CasbinRule } from "./model"
import { MongooseAdapter } from "./index"

const RuleModel = getModelForClass(CasbinRule)

const mongoUri = process.env.MONGO_ADDR || "mongodb://localhost"

describe("Mongoose adapter", () => {
  let adapter: MongooseAdapter
  beforeAll(async done => {
    await connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    adapter = new MongooseAdapter()
    done()
  })
  beforeEach(async done => {
    await RuleModel.deleteMany({})
    done()
  })
  test("can create adapter", () => {
    expect(new MongooseAdapter()).toBeTruthy()
  })
  test("can load empty policies", async done => {
    const enforcer = await newEnforcer(
      resolve(__dirname, "./fixtures/basic_model.conf"),
      adapter
    )
    expect(await enforcer.getPolicy()).toEqual([])
    done()
  })
  test("can store new policy", async done => {
    const enforcer = await newEnforcer(
      resolve(__dirname, "./fixtures/basic_model.conf"),
      adapter
    )
    const oldRules = await RuleModel.find({})
    expect(oldRules).toEqual([])
    const newRule = ["sub", "obj", "act"]
    expect(await enforcer.addPolicy(...newRule))
    expect(await enforcer.getPolicy()).toEqual([newRule])
    const newRules = await RuleModel.find({
      p_type: "p",
      v0: newRule[0],
      v1: newRule[1],
      v2: newRule[2]
    })
    expect(newRules).toHaveLength(1)
    done()
  })
  test("can add and remove policy", async done => {
    let enforcer = await newEnforcer(
      resolve(__dirname, "fixtures", "rbac_model.conf"),
      resolve(__dirname, "fixtures", "rbac_policy.csv")
    )
    const oldRules = await RuleModel.find({})
    expect(oldRules).toEqual([])
    await adapter.savePolicy(enforcer.getModel())
    const newRules = await RuleModel.find({})
    expect(
      newRules.map(rule => [rule.p_type, rule.v0, rule.v1, rule.v2])
    ).toEqual([
      ["p", "alice", "data1", "read"],
      ["p", "bob", "data2", "write"],
      ["p", "data2_admin", "data2", "read"],
      ["p", "data2_admin", "data2", "write"],
      ["g", "alice", "data2_admin", undefined]
    ])
    const newPolicy: Parameters<MongooseAdapter["addPolicy"]> = [
      "",
      "p",
      ["role", "res", "action"]
    ]
    await adapter.addPolicy(...newPolicy)
    enforcer = await newEnforcer(
      resolve(__dirname, "fixtures", "rbac_model.conf"),
      adapter
    )
    expect(await enforcer.getPolicy()).toEqual([
      ["alice", "data1", "read"],
      ["bob", "data2", "write"],
      ["data2_admin", "data2", "read"],
      ["data2_admin", "data2", "write"],
      ["role", "res", "action"]
    ])
    done()
  })
  afterAll(async () => {
    RuleModel.deleteMany({})
    disconnect()
  })
})
