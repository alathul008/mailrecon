export type Module={module:string;status:string;message?:string};
export type Finding={id:number;source:string;source_url?:string;finding_type:string;value:string;confidence:number;severity:string;collected_at:string;notes?:string;evidence_state?:string|null;execution_id?:string|number|null;execution_attempt_id?:string|number|null;current_attempt?:boolean|null};
export type Investigation={id:number;target:string;username:string;domain:string;status:string;risk_score:number|null;risk_level:string|null;created_at:string;completed_at?:string;modules:Module[];findings:Finding[]};

export type TimelineEvent={id:number;timestamp:string;last_seen?:string|null;collected_at:string;kind:string;label:string;source:string;value:string;severity:string;confidence:number;evidence_state?:string|null;execution_attempt_id?:string|number|null;current_attempt?:boolean|null};
