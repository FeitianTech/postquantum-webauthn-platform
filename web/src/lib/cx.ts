// Joins class names, skipping the ones a condition turned off.
export function cx(...names: Array<string | false | null | undefined>): string {
  return names.filter(Boolean).join(' ');
}
