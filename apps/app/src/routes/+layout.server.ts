import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ locals }) => {
  return {
    clientIp: locals.clientIp,
    cfRay: locals.cfRay,
  };
};
