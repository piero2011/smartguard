import { isLocalAddress } from '../../src/common/security';
import { ConfigService } from '../../src/config/config.service';
import { testEnv } from '../helpers';

describe('Conexiones locales (LOCAL_NETWORKS, para despliegues en contenedores)', () => {
  it('por defecto solo loopback', () => {
    const config = new ConfigService(testEnv());
    expect(isLocalAddress('127.0.0.1', config)).toBe(true);
    expect(isLocalAddress('::1', config)).toBe(true);
    expect(isLocalAddress('::ffff:127.0.0.1', config)).toBe(true);
    expect(isLocalAddress('172.30.77.3', config)).toBe(false);
    expect(isLocalAddress('203.0.113.9', config)).toBe(false);
    expect(isLocalAddress(undefined, config)).toBe(false);
  });

  it('con LOCAL_NETWORKS acepta esa red y nada más', () => {
    const config = new ConfigService(testEnv({ LOCAL_NETWORKS: '172.30.77.0/24' }));
    expect(isLocalAddress('172.30.77.1', config)).toBe(true);
    expect(isLocalAddress('172.30.77.250', config)).toBe(true);
    expect(isLocalAddress('::ffff:172.30.77.3', config)).toBe(true);
    expect(isLocalAddress('172.30.78.1', config)).toBe(false);
    expect(isLocalAddress('203.0.113.9', config)).toBe(false);
    expect(isLocalAddress('no-es-una-ip', config)).toBe(false);
    expect(isLocalAddress('127.0.0.1', config)).toBe(true);
  });
});
