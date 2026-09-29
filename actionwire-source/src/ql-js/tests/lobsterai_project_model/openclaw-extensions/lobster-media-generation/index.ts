export function registerMediaTools(api: { registerTool(factory: unknown): void }) {
  api.registerTool((_ctx: unknown) => {
    return {
      name: "lobsterai_image_generate",
      async execute(_id: string, params: unknown) {
        return params;
      },
    };
  });

  api.registerTool((_ctx: unknown) => {
    return {
      name: "lobsterai_video_generate",
      async execute(_id: string, params: unknown) {
        return params;
      },
    };
  });
}
