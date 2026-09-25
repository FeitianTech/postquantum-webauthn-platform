import type { HTMLAttributes, ReactNode } from 'react';

import { cx } from '@/lib/cx';

type CardProps = Omit<HTMLAttributes<HTMLElement>, 'style'> & { as?: 'section' | 'div' | 'article' };

// A white section with a hairline. Cards never nest: inside one, separate parts
// with space and hairlines.
export function Card({ as: Tag = 'section', className, children, ...props }: CardProps) {
  return (
    <Tag className={cx('min-w-0 rounded-lg border border-line bg-surface p-5 sm:p-7', className)} {...props}>
      {children}
    </Tag>
  );
}

type CardHeaderProps = {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  titleAs?: 'h2' | 'h3';
  titleId?: string;
};

export function CardHeader({ title, description, actions, titleAs: Title = 'h3', titleId }: CardHeaderProps) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
      <div className="min-w-0 flex-1">
        <Title id={titleId} className="text-title-sm font-semibold text-ink">
          {title}
        </Title>
        {description ? <p className="mt-1 max-w-prose text-body text-ink-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
