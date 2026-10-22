// The news posts (vite.config.ts), newest first: the date as YYYY-MM-DD and the text as HTML.
declare module "virtual:news" {
  const posts: { date: string; slug: string; title: string; html: string }[];
  export default posts;
}
