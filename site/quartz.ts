import { loadQuartzConfig, loadQuartzLayout } from "./quartz/plugins/loader/config-loader"

const config = await loadQuartzConfig({
  pageTitle: "SAD - Seguridad y Alta Disponibilidad",
  locale: "es-ES",
  baseUrl: "raulb1zkit.github.io/SAD-1AVAL",
  theme: {
    fontOrigin: "local",
  },
})

export default config
export const layout = await loadQuartzLayout()
