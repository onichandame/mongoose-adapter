import { FilteredAdapter, Filter, Model } from 'casbin';
import { Connection, connection } from 'mongoose';

/*
 * This class does not create mongoose connection. You need to create a connection then pass it to the constructor of this class.
 * If connection not passed, the default mongoose connection will be used
 */
export class MongooseAdapter implements FilteredAdapter {
  public connection: Connection;
  private _isFiltered: boolean = false;
  constructor(con: Connection = connection) {
    this.connection = con;
  }
  public isFiltered() {
    return this._isFiltered;
  }
  public async loadFilteredPolicy(model: Model, filter: Filter) {}
  public async loadPolicy(model: Model) {}
  public async savePolicy(model: Model) {
    return true;
  }
  public async addPolicy(sec: string, ptype: string, rule: string[]) {}
  public async removePolicy(sec: string, ptype: string, rule: string[]) {}
  public async removeFilteredPolicy(
    sec: string,
    ptype: string,
    fieldIndex: number,
    ...fieldValues: string[]
  ) {}
}
