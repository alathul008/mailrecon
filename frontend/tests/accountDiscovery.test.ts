import {describe,expect,it} from 'vitest';
import {parseRoute} from '../src/App';

describe('account discovery navigation',()=>{
  it('routes the account discovery tab deterministically',()=>{
    expect(parseRoute('#/investigation/42/account-discovery')).toEqual({page:'Investigation',id:42,tab:'Account Discovery'});
  });
  it('rejects unknown investigation tabs',()=>{
    expect(parseRoute('#/investigation/42/not-a-real-tab')).toEqual({page:'Dashboard'});
  });
});
