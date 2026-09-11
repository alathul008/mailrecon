import {describe,expect,it} from 'vitest';
import {CorrelationPanel} from '../src/components/CorrelationPanel';

describe('correlation panel contract',()=>{
  it('exports a renderable analyst-facing correlation component',()=>{
    expect(typeof CorrelationPanel).toBe('function');
  });
});
