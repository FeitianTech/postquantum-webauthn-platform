import { Button } from '@/components/ui/Button';
import { useSectionNavigation } from '@/lib/useSection';

// "Decode in Codec": opens the Codec with `payload` in its input, decoded. The
// payload goes through the section router (the URL is #codec alone), and Back
// returns here. Named for the part it decodes ("Decode in Codec: client data");
// a row of parts gives each its own word as the label. Nothing without a payload.
export function DecodeInCodec({
  part,
  payload,
  label,
  onLeave,
}: {
  part: string;
  payload: string;
  /** The button's own word, in a group that names what it does. */
  label?: string;
  /** Called with the button as it opens the Codec. */
  onLeave?: (button: HTMLButtonElement) => void;
}) {
  const go = useSectionNavigation();
  if (!payload) return null;
  return (
    <Button
      variant="secondary"
      size="sm"
      className="shrink-0"
      data-decode={part}
      aria-label={label ? undefined : `Decode in Codec: ${part}`}
      onClick={(event) => {
        onLeave?.(event.currentTarget);
        go('codec', [], { kind: 'decode', payload });
      }}
    >
      {label ?? 'Decode in Codec'}
    </Button>
  );
}
