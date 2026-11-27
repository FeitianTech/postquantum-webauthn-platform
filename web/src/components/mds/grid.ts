// A row of the MDS table, and its header: a grid of two lines that fits the
// page's width, so nothing scrolls sideways. A column is there from the width at
// which it fits beside the name over the ID (never narrower than a whole
// identifier and its copy button): the status over the protocol and the date
// from 768 px, the transports over the attachment from 1024, the algorithms from
// 1152, the user verification from 1408. A narrower window stacks the name, the
// ID, and a third line. The tracks do not depend on what a row holds, so every
// row and the header line up.
export const ROW_GRID =
  'grid grid-cols-[2.75rem_auto_auto_minmax(0,1fr)] md:grid-cols-[2.75rem_minmax(0,1fr)_9.5rem_8rem] lg:grid-cols-[2.75rem_minmax(22rem,1fr)_9.5rem_11.75rem_8rem] min-[72rem]:grid-cols-[2.75rem_minmax(22rem,1fr)_9.5rem_11.75rem_minmax(0,14rem)_8rem] min-[88rem]:grid-cols-[2.75rem_minmax(22rem,1fr)_9.5rem_11.75rem_minmax(0,11.5rem)_minmax(0,14rem)_8rem]';
